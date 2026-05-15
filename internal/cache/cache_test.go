package cache

import (
	"testing"
	"time"
)

func TestTTLCacheExpiresEntriesOnRead(t *testing.T) {
	t.Parallel()

	ttlCache := New(Options{MaxEntries: 8, CleanupInterval: time.Hour})
	t.Cleanup(ttlCache.Stop)

	ttlCache.Set("expired", "value", -time.Second)

	if got, ok := ttlCache.Get("expired"); ok || got != nil {
		t.Fatalf("expected expired entry to miss, got=%v ok=%v", got, ok)
	}
}

func TestTTLCacheEvictsOldestWhenFull(t *testing.T) {
	t.Parallel()

	ttlCache := New(Options{MaxEntries: 2, CleanupInterval: time.Hour})
	t.Cleanup(ttlCache.Stop)

	ttlCache.Set("first", "a", time.Minute)
	time.Sleep(time.Millisecond)
	ttlCache.Set("second", "b", 2*time.Minute)
	ttlCache.Set("third", "c", 3*time.Minute)

	if _, ok := ttlCache.Get("first"); ok {
		t.Fatalf("expected oldest entry to be evicted")
	}
	if got, ok := ttlCache.Get("second"); !ok || got != "b" {
		t.Fatalf("expected second entry to remain, got=%v ok=%v", got, ok)
	}
	if got, ok := ttlCache.Get("third"); !ok || got != "c" {
		t.Fatalf("expected third entry to remain, got=%v ok=%v", got, ok)
	}
}
