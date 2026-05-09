package geoip

import (
	"errors"
	"testing"
)

func TestOpen_EmptyPath(t *testing.T) {
	r, err := Open("")
	if !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("expected ErrNoDatabase, got %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
	if _, ok := r.Lookup("8.8.8.8"); ok {
		t.Fatal("no-op resolver must not return ok=true")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestOpen_MissingFile(t *testing.T) {
	r, err := Open("/path/does/not/exist.mmdb")
	if !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("expected ErrNoDatabase, got %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver even for missing file")
	}
}

func TestLookup_NoOpResolver(t *testing.T) {
	var r *Resolver
	if _, ok := r.Lookup("1.1.1.1"); ok {
		t.Fatal("nil resolver must return ok=false")
	}
}

func TestLookup_PrivateIPsReturnFalse(t *testing.T) {
	// Use no-op resolver but exercise the private filter path.
	r := &Resolver{cache: map[string]Location{}}
	cases := []string{
		"10.0.0.5",
		"192.168.1.10",
		"172.16.5.5",
		"127.0.0.1",
		"::1",
		"169.254.1.1",
	}
	for _, ip := range cases {
		if _, ok := r.Lookup(ip); ok {
			t.Fatalf("expected ok=false for private %s", ip)
		}
	}
}

func TestLookup_CacheHonoursMissResults(t *testing.T) {
	r := &Resolver{cache: map[string]Location{}}
	r.cacheStore("1.2.3.4", Location{})
	if loc, ok := r.Lookup("1.2.3.4"); ok || loc.Country != "" {
		t.Fatalf("cached miss must return ok=false; got %+v ok=%v", loc, ok)
	}
}

func TestCacheStore_BoundedSize(t *testing.T) {
	r := &Resolver{cache: map[string]Location{}}
	for i := 0; i < maxCacheEntries+50; i++ {
		r.cacheStore(string(rune(i)), Location{Country: "X"})
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.cache) > maxCacheEntries {
		t.Fatalf("cache exceeded max: %d", len(r.cache))
	}
}
