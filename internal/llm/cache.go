package llm

import (
	"crypto/md5"
	"fmt"
	"sync"
	"time"
)

// AnalysisCache stores analyzed requests to avoid repeated API calls
type AnalysisCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	ttl     time.Duration
}

type CacheEntry struct {
	Result    *AnalysisResult
	Timestamp time.Time
	HitCount  int
}

// NewAnalysisCache creates a new analysis cache with TTL
func NewAnalysisCache(ttl time.Duration) *AnalysisCache {
	cache := &AnalysisCache{
		entries: make(map[string]*CacheEntry),
		ttl:     ttl,
	}

	// Start cleanup goroutine
	go cache.cleanupExpired()

	return cache
}

// GetHash generates a hash of the request data for cache key
func (ac *AnalysisCache) GetHash(requestData map[string]string) string {
	// Use method, path, and query for consistency
	key := fmt.Sprintf("%s|%s|%s|%s",
		requestData["method"],
		requestData["path"],
		requestData["query"],
		requestData["body"],
	)
	hash := md5.Sum([]byte(key))
	return fmt.Sprintf("%x", hash)
}

// Get retrieves a cached analysis result
func (ac *AnalysisCache) Get(requestData map[string]string) (*AnalysisResult, bool) {
	hash := ac.GetHash(requestData)

	ac.mu.RLock()
	defer ac.mu.RUnlock()

	entry, exists := ac.entries[hash]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Since(entry.Timestamp) > ac.ttl {
		return nil, false
	}

	return entry.Result, true
}

// Set stores an analysis result in cache
func (ac *AnalysisCache) Set(requestData map[string]string, result *AnalysisResult) {
	hash := ac.GetHash(requestData)

	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.entries[hash] = &CacheEntry{
		Result:    result,
		Timestamp: time.Now(),
		HitCount:  0,
	}
}

// Hit increments the hit count for a cached entry
func (ac *AnalysisCache) Hit(requestData map[string]string) {
	hash := ac.GetHash(requestData)

	ac.mu.Lock()
	defer ac.mu.Unlock()

	if entry, exists := ac.entries[hash]; exists {
		entry.HitCount++
	}
}

// cleanupExpired removes expired entries every 5 minutes
func (ac *AnalysisCache) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ac.mu.Lock()

		now := time.Now()
		for hash, entry := range ac.entries {
			if now.Sub(entry.Timestamp) > ac.ttl {
				delete(ac.entries, hash)
			}
		}

		ac.mu.Unlock()
	}
}

// Stats returns cache statistics
func (ac *AnalysisCache) Stats() map[string]interface{} {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	totalHits := 0
	for _, entry := range ac.entries {
		totalHits += entry.HitCount
	}

	return map[string]interface{}{
		"cached_entries": len(ac.entries),
		"total_hits":     totalHits,
		"ttl_seconds":    ac.ttl.Seconds(),
	}
}

// Clear removes all entries from cache
func (ac *AnalysisCache) Clear() {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.entries = make(map[string]*CacheEntry)
}
