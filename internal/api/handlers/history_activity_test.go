package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crowdsec-manager/internal/history"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

type fakeHistoryActivityService struct {
	result history.ActivityBuckets
	err    error
	input  history.GetActivityBucketsInput
}

func init() {
	gin.SetMode(gin.TestMode)
}

func (s *fakeHistoryActivityService) GetActivityBuckets(_ context.Context, in history.GetActivityBucketsInput) (history.ActivityBuckets, error) {
	s.input = in
	if s.err != nil {
		return history.ActivityBuckets{}, s.err
	}
	return s.result, nil
}

func TestParseHistoryActivityParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		window     string
		bucket     string
		wantErr    bool
		wantWin    string
		wantBucket string
	}{
		{name: "defaults", window: "", bucket: "", wantErr: false, wantWin: "24h", wantBucket: "hour"},
		{name: "24h_hour", window: "24h", bucket: "hour", wantErr: false, wantWin: "24h", wantBucket: "hour"},
		{name: "7d_day", window: "7d", bucket: "day", wantErr: false, wantWin: "7d", wantBucket: "day"},
		{name: "invalid_window", window: "30d", bucket: "day", wantErr: true},
		{name: "invalid_24h_bucket", window: "24h", bucket: "day", wantErr: true},
		{name: "invalid_7d_bucket", window: "7d", bucket: "hour", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			q := req.URL.Query()
			if tc.window != "" {
				q.Set("window", tc.window)
			}
			if tc.bucket != "" {
				q.Set("bucket", tc.bucket)
			}
			req.URL.RawQuery = q.Encode()
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			gotWindow, gotBucket, _, err := parseHistoryActivityParams(c)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotWindow != tc.wantWin {
				t.Fatalf("window mismatch: got %q want %q", gotWindow, tc.wantWin)
			}
			if string(gotBucket) != tc.wantBucket {
				t.Fatalf("bucket mismatch: got %q want %q", gotBucket, tc.wantBucket)
			}
		})
	}
}

func TestGetHistoryActivityHTTP(t *testing.T) {
	t.Parallel()

	latest := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		target     string
		service    *fakeHistoryActivityService
		wantStatus int
		wantOK     bool
		wantWindow string
		wantBucket string
		wantCount  int
		wantError  string
	}{
		{
			name:       "defaults",
			target:     "/history/activity",
			service:    newFakeHistoryActivityService(24, &latest),
			wantStatus: http.StatusOK,
			wantOK:     true,
			wantWindow: historyActivityWindow24h,
			wantBucket: string(history.ActivityBucketHour),
			wantCount:  24,
		},
		{
			name:       "valid 24h hour",
			target:     "/history/activity?window=24h&bucket=hour",
			service:    newFakeHistoryActivityService(24, &latest),
			wantStatus: http.StatusOK,
			wantOK:     true,
			wantWindow: historyActivityWindow24h,
			wantBucket: string(history.ActivityBucketHour),
			wantCount:  24,
		},
		{
			name:       "valid 7d day",
			target:     "/history/activity?window=7d&bucket=day",
			service:    newFakeHistoryActivityService(7, &latest),
			wantStatus: http.StatusOK,
			wantOK:     true,
			wantWindow: historyActivityWindow7d,
			wantBucket: string(history.ActivityBucketDay),
			wantCount:  7,
		},
		{
			name:       "invalid window",
			target:     "/history/activity?window=bad",
			service:    newFakeHistoryActivityService(0, nil),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid bucket",
			target:     "/history/activity?bucket=bad",
			service:    newFakeHistoryActivityService(0, nil),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid 24h day combo",
			target:     "/history/activity?window=24h&bucket=day",
			service:    newFakeHistoryActivityService(0, nil),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid 7d hour combo",
			target:     "/history/activity?window=7d&bucket=hour",
			service:    newFakeHistoryActivityService(0, nil),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "nil service",
			target:     "/history/activity",
			service:    nil,
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "store unavailable",
			target:     "/history/activity",
			service:    &fakeHistoryActivityService{err: history.ErrStoreUnavailable},
			wantStatus: http.StatusServiceUnavailable,
			wantError:  "history unavailable",
		},
		{
			name:       "query failure",
			target:     "/history/activity",
			service:    &fakeHistoryActivityService{err: errors.New("database closed")},
			wantStatus: http.StatusInternalServerError,
			wantError:  "history error",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			router := gin.New()
			router.GET("/history/activity", getHistoryActivity(tc.service))

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status mismatch: got %d want %d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}

			var envelope struct {
				Success bool                            `json:"success"`
				Data    *models.HistoryActivityResponse `json:"data"`
				Error   string                          `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			if tc.wantOK {
				if !envelope.Success {
					t.Fatalf("expected success response, got error %q", envelope.Error)
				}
				if envelope.Data == nil {
					t.Fatalf("expected response data")
				}
				if envelope.Data.Window != tc.wantWindow {
					t.Fatalf("window mismatch: got %q want %q", envelope.Data.Window, tc.wantWindow)
				}
				if envelope.Data.Bucket != tc.wantBucket {
					t.Fatalf("bucket mismatch: got %q want %q", envelope.Data.Bucket, tc.wantBucket)
				}
				if len(envelope.Data.Buckets) != tc.wantCount {
					t.Fatalf("bucket count mismatch: got %d want %d", len(envelope.Data.Buckets), tc.wantCount)
				}
				if envelope.Data.GeneratedAt == "" {
					t.Fatalf("expected generated_at")
				}
				if envelope.Data.LatestSnapshotAt == nil {
					t.Fatalf("expected latest_snapshot_at")
				}
				if _, err := time.Parse(time.RFC3339, envelope.Data.GeneratedAt); err != nil {
					t.Fatalf("generated_at is not RFC3339: %v", err)
				}
				return
			}

			if envelope.Success {
				t.Fatalf("expected unsuccessful response")
			}
			if envelope.Error == "" {
				t.Fatalf("expected error message")
			}
			if tc.wantError != "" && envelope.Error != tc.wantError {
				t.Fatalf("error mismatch: got %q want %q", envelope.Error, tc.wantError)
			}
		})
	}
}

func TestGetHistoryActivityDailyEndsAfterCurrentUTCDay(t *testing.T) {
	t.Parallel()

	service := newFakeHistoryActivityService(7, nil)
	router := gin.New()
	router.GET("/history/activity", getHistoryActivity(service))

	nowUTCPre := time.Now().UTC()
	wantEndAtPre := time.Date(nowUTCPre.Year(), nowUTCPre.Month(), nowUTCPre.Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/history/activity?window=7d&bucket=day", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status mismatch: got %d want %d body=%s", w.Code, http.StatusOK, w.Body.String())
	}

	nowUTCPost := time.Now().UTC()
	wantEndAtPost := time.Date(nowUTCPost.Year(), nowUTCPost.Month(), nowUTCPost.Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
	if !service.input.EndAt.Equal(wantEndAtPre) && !service.input.EndAt.Equal(wantEndAtPost) {
		t.Fatalf(
			"daily endAt mismatch: got %s want %s or %s",
			service.input.EndAt.Format(time.RFC3339),
			wantEndAtPre.Format(time.RFC3339),
			wantEndAtPost.Format(time.RFC3339),
		)
	}
}

func newFakeHistoryActivityService(count int, latest *time.Time) *fakeHistoryActivityService {
	buckets := make([]models.HistoryActivityBucket, 0, count)
	start := time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC)
	for i := 0; i < count; i++ {
		buckets = append(buckets, models.HistoryActivityBucket{
			Timestamp: start.Add(time.Duration(i) * time.Hour).Format(time.RFC3339),
			Alerts:    i % 2,
			Decisions: (i + 1) % 2,
		})
	}
	return &fakeHistoryActivityService{
		result: history.ActivityBuckets{
			Buckets:          buckets,
			LatestSnapshotAt: latest,
		},
	}
}
