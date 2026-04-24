package handlers

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"time"

	"crowdsec-manager/internal/history"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

const (
	historyActivityWindow24h = "24h"
	historyActivityWindow7d  = "7d"
)

type historyActivityQuerier interface {
	GetActivityBuckets(context.Context, history.GetActivityBucketsInput) (history.ActivityBuckets, error)
}

// GetHistoryActivity returns UTC-aligned, gap-filled dashboard activity buckets.
func GetHistoryActivity() gin.HandlerFunc {
	if historyService == nil {
		return getHistoryActivity(nil)
	}
	return getHistoryActivity(historyService)
}

func getHistoryActivity(service historyActivityQuerier) gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		window, bucket, duration, err := parseHistoryActivityParams(c)
		if err != nil {
			logHistoryActivityRequest(c, window, string(bucket), http.StatusBadRequest, time.Since(started))
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: err.Error()})
			return
		}

		if historyActivityServiceUnavailable(service) {
			logHistoryActivityRequest(c, window, string(bucket), http.StatusServiceUnavailable, time.Since(started))
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history unavailable"})
			return
		}

		nowUTC := time.Now().UTC()
		endAt := nowUTC.Truncate(time.Hour)
		if bucket == history.ActivityBucketDay {
			endAt = time.Date(nowUTC.Year(), nowUTC.Month(), nowUTC.Day(), 0, 0, 0, 0, time.UTC)
		}

		result, err := service.GetActivityBuckets(c.Request.Context(), history.GetActivityBucketsInput{
			Window: duration,
			Bucket: bucket,
			EndAt:  endAt,
		})
		if err != nil {
			if !errors.Is(err, history.ErrStoreUnavailable) {
				logger.Warn("Failed to load history activity", "error", err)
			}
			logHistoryActivityRequest(c, window, string(bucket), http.StatusServiceUnavailable, time.Since(started))
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history unavailable"})
			return
		}

		var latestSnapshotAt *string
		if result.LatestSnapshotAt != nil {
			formatted := result.LatestSnapshotAt.UTC().Format(time.RFC3339)
			latestSnapshotAt = &formatted
		}

		response := models.HistoryActivityResponse{
			Window:           window,
			Bucket:           string(bucket),
			GeneratedAt:      nowUTC.Format(time.RFC3339),
			LatestSnapshotAt: latestSnapshotAt,
			Buckets:          result.Buckets,
		}

		logHistoryActivityRequest(c, window, string(bucket), http.StatusOK, time.Since(started))
		c.JSON(http.StatusOK, models.Response{Success: true, Data: response})
	}
}

func historyActivityServiceUnavailable(service historyActivityQuerier) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func parseHistoryActivityParams(c *gin.Context) (string, history.ActivityBucket, time.Duration, error) {
	window := c.DefaultQuery("window", historyActivityWindow24h)
	rawBucket := c.Query("bucket")
	if rawBucket == "" {
		if window == historyActivityWindow7d {
			rawBucket = string(history.ActivityBucketDay)
		} else {
			rawBucket = string(history.ActivityBucketHour)
		}
	}

	var duration time.Duration
	switch window {
	case historyActivityWindow24h:
		duration = 24 * time.Hour
	case historyActivityWindow7d:
		duration = 7 * 24 * time.Hour
	default:
		return window, history.ActivityBucket(rawBucket), 0, errors.New("window must be one of 24h or 7d")
	}

	bucket := history.ActivityBucket(rawBucket)
	switch bucket {
	case history.ActivityBucketHour, history.ActivityBucketDay:
	default:
		return window, bucket, 0, errors.New("bucket must be one of hour or day")
	}

	if window == historyActivityWindow24h && bucket != history.ActivityBucketHour {
		return window, bucket, 0, errors.New("window=24h requires bucket=hour")
	}
	if window == historyActivityWindow7d && bucket != history.ActivityBucketDay {
		return window, bucket, 0, errors.New("window=7d requires bucket=day")
	}

	return window, bucket, duration, nil
}

func logHistoryActivityRequest(c *gin.Context, window string, bucket string, status int, duration time.Duration) {
	fields := []any{
		"path", c.Request.URL.Path,
		"window", window,
		"bucket", bucket,
		"status", status,
		"duration_ms", duration.Milliseconds(),
	}
	if requestID := historyActivityRequestID(c); requestID != "" {
		fields = append(fields, "request_id", requestID)
	}
	logger.Debug("History activity request", fields...)
}

func historyActivityRequestID(c *gin.Context) string {
	for _, header := range []string{"X-Request-ID", "X-Request-Id", "X-Correlation-ID"} {
		if value := c.GetHeader(header); value != "" {
			return value
		}
	}
	return ""
}
