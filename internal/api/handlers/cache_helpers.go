package handlers

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"crowdsec-manager/internal/cache"

	"github.com/gin-gonic/gin"
)

const (
	crowdSecAnalysisCachePrefix       = "crowdsec:analysis:"
	alertLastNonEmptyCachePrefix      = "crowdsec:analysis:last-non-empty:"
	decisionListCachePrefix           = "decisions"
	analysisCacheTTL                  = 30 * time.Second
	emptyAnalysisCacheTTL             = 5 * time.Second
	alertLastNonEmptyAnalysisCacheTTL = 2 * time.Minute
)

func optionalCache(ttlCache []*cache.TTLCache) *cache.TTLCache {
	if len(ttlCache) == 0 {
		return nil
	}
	return ttlCache[0]
}

func crowdSecAnalysisCacheKey(c *gin.Context, endpoint string) string {
	return crowdSecAnalysisCachePrefix + crowdSecAnalysisCacheSuffix(c, endpoint)
}

func alertLastNonEmptyAnalysisCacheKey(c *gin.Context) string {
	return alertLastNonEmptyCachePrefix + crowdSecAnalysisCacheSuffix(c, "alerts")
}

func crowdSecAnalysisCacheSuffix(c *gin.Context, endpoint string) string {
	return endpoint + ":host=" + selectedDockerHost(c) + ":query=" + stableQuery(c.Request.URL.Query())
}

func selectedDockerHost(c *gin.Context) string {
	host := c.Query("host")
	if host == "" {
		host = c.GetHeader("X-Docker-Host")
	}
	if host == "" {
		return "default"
	}
	return host
}

func stableQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key == "host" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		vals := append([]string(nil), values[key]...)
		sort.Strings(vals)
		for _, value := range vals {
			parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(value))
		}
	}
	return strings.Join(parts, "&")
}

func invalidateCrowdSecDataCache(ttlCache ...*cache.TTLCache) {
	c := optionalCache(ttlCache)
	if c == nil {
		return
	}
	c.DeletePrefix(crowdSecAnalysisCachePrefix)
	c.DeletePrefix(alertLastNonEmptyCachePrefix)
	c.DeletePrefix(decisionListCachePrefix)
}
