/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package vault

import (
	"sync"
	"time"
)

type tokenCacheEntry struct {
	token  string
	expiry time.Time
}

// TokenCache is a thread-safe cache mapping string keys to Vault client tokens with TTL-based
// expiry. Entries are evicted lazily when accessed after their TTL.
type TokenCache struct {
	mu      sync.RWMutex
	entries map[string]*tokenCacheEntry
}

// NewTokenCache creates a new empty token cache.
func NewTokenCache() *TokenCache {
	return &TokenCache{
		entries: make(map[string]*tokenCacheEntry),
	}
}

// Get returns the cached Vault token for the given key, or empty string and false if the entry
// does not exist or has expired.
func (c *TokenCache) Get(key string) (string, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiry) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return "", false
	}
	return entry.token, true
}

// Put stores a Vault token with the given TTL. The entry is evicted after the TTL elapses.
func (c *TokenCache) Put(key, token string, ttl time.Duration) {
	c.mu.Lock()
	c.entries[key] = &tokenCacheEntry{
		token:  token,
		expiry: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}
