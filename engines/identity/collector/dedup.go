/*
rexdr - Active Directory Intelligence Engine
collector/dedup.go - Multi-DC event deduplication tracker

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Tracks recently seen event dedup keys to prevent duplicate
          ingestion when the same security event replicates across
          multiple domain controllers. Uses a simple time-bounded
          in-memory set with periodic cleanup.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

--- Part of the REXDR platform. ---
*/

package main

import (
	"sync"
	"time"
)

type DedupTracker struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

func newDedupTracker() *DedupTracker {
	d := &DedupTracker{
		seen: make(map[string]time.Time),
		ttl:  10 * time.Minute,
	}
	go d.cleanupLoop()
	return d
}

func (d *DedupTracker) isDuplicate(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.seen[key]; exists {
		return true
	}

	d.seen[key] = time.Now()
	return false
}

func (d *DedupTracker) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.mu.Lock()
		now := time.Now()
		for key, seenAt := range d.seen {
			if now.Sub(seenAt) > d.ttl {
				delete(d.seen, key)
			}
		}
		d.mu.Unlock()
	}
}
