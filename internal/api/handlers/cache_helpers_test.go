package handlers

import (
	"net/http/httptest"
	"testing"
	"time"

	"crowdsec-manager/internal/cache"

	"github.com/gin-gonic/gin"
)

func TestCrowdSecAnalysisCacheKeyStableAndHostAware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	keyA := cacheKeyForRequest(t, "/alerts/analysis?scenario=crowdsecurity/http-probing&since=7d&type=ban&host=edge")
	keyB := cacheKeyForRequest(t, "/alerts/analysis?type=ban&host=edge&since=7d&scenario=crowdsecurity/http-probing")
	if keyA != keyB {
		t.Fatalf("cache key should be stable across query ordering:\n%s\n%s", keyA, keyB)
	}

	keyC := cacheKeyForRequest(t, "/alerts/analysis?scenario=crowdsecurity/http-probing&since=7d&type=ban")
	if keyA == keyC {
		t.Fatalf("cache key should include selected docker host")
	}
}

func TestInvalidateCrowdSecDataCache(t *testing.T) {
	ttlCache := cache.New()
	ttlCache.Set("crowdsec:analysis:alerts:host=default:query=since=7d", "alerts", time.Minute)
	ttlCache.Set("crowdsec:analysis:decisions:host=default:query=type=ban", "decisions", time.Minute)
	ttlCache.Set("decisions-summary", "summary", time.Minute)
	ttlCache.Set("metrics", "metrics", time.Minute)

	invalidateCrowdSecDataCache(ttlCache)

	if _, ok := ttlCache.Get("crowdsec:analysis:alerts:host=default:query=since=7d"); ok {
		t.Fatalf("expected alerts analysis cache to be invalidated")
	}
	if _, ok := ttlCache.Get("crowdsec:analysis:decisions:host=default:query=type=ban"); ok {
		t.Fatalf("expected decisions analysis cache to be invalidated")
	}
	if _, ok := ttlCache.Get("decisions-summary"); ok {
		t.Fatalf("expected decision list cache to be invalidated")
	}
	if got, ok := ttlCache.Get("metrics"); !ok || got != "metrics" {
		t.Fatalf("metrics cache should be left intact, got=%v ok=%v", got, ok)
	}
}

func cacheKeyForRequest(t *testing.T, target string) string {
	t.Helper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", target, nil)
	return crowdSecAnalysisCacheKey(c, "alerts")
}
