// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package token

import (
	"fmt"
	"sync"
	"unsafe"
)

type TokenCache interface {
	Store(k CacheKey, t Token)
	Load(k CacheKey) Token
	Range(func(k CacheKey, t Token) error) error
	Keys() []CacheKey
	Size() int64
	Len() int
	Clear()
}

type CacheKey struct {
	Domain            string
	MaxExpiry         int
	MinExpiry         int
	ProxyForPrincipal string
	Role              string
}

func (k CacheKey) String() string {
	return fmt.Sprintf("{%s:role.%s,%s,%d,%d}", k.Domain, k.Role, k.ProxyForPrincipal, k.MinExpiry, k.MaxExpiry)
}

func (k CacheKey) Size() uint {
	structSize := uint(unsafe.Sizeof(k))
	// unsafe.Sizeof() ONLY count the string struct, need to count the actual string block explicitly
	stringSize := len(k.Domain) + len(k.ProxyForPrincipal) + len(k.Role)
	return structSize + uint(stringSize)
}

type LockedTokenCache struct {
	cache map[CacheKey]Token
	lock  sync.RWMutex

	// memoryUsage is the estimated number of bytes used by the cache.
	memoryUsage int64
}

func NewLockedTokenCache() *LockedTokenCache {
	return &LockedTokenCache{
		cache:       make(map[CacheKey]Token),
		memoryUsage: 0,
	}
}

func (c *LockedTokenCache) Store(k CacheKey, t Token) {
	c.lock.Lock()
	defer c.lock.Unlock()
	oldToken, ok := c.cache[k]
	c.cache[k] = t

	// update cache memory usage
	tokenSize := t.Size()
	if ok {
		c.memoryUsage += int64(tokenSize) - int64(oldToken.Size())
	} else {
		c.memoryUsage += int64(k.Size() + tokenSize)
	}
}

func (c *LockedTokenCache) Load(k CacheKey) Token {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.cache[k]
}

func (c *LockedTokenCache) Range(f func(k CacheKey, t Token) error) error {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for key, token := range c.cache {
		err := f(key, token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *LockedTokenCache) Keys() []CacheKey {
	c.lock.RLock()
	defer c.lock.RUnlock()
	r := make([]CacheKey, 0, len(c.cache))
	c.Range(func(k CacheKey, t Token) error {
		r = append(r, k)
		return nil
	})
	return r
}

func (c *LockedTokenCache) Size() int64 {
	// structSize := uint(unsafe.Sizeof(*c)) // should equal to the following sizes
	cacheSize := uint(unsafe.Sizeof(c.cache)) // not exact, there are hidden variables in map
	lockSize := uint(unsafe.Sizeof(c.lock))   // not exact, there are hidden variables in sync.RWMutex
	memSize := uint(unsafe.Sizeof(c.memoryUsage))

	// estimate hidden bucket allocation by map
	_, bSize := getMapBucketLenAndSize(c.cache)

	return int64(cacheSize+lockSize+memSize) + c.memoryUsage + bSize
}

func (c *LockedTokenCache) Len() int {
	return len(c.cache)
}

func (c *LockedTokenCache) Clear() {
	c.lock.Lock()
	defer c.lock.Unlock()
	for t := range c.cache {
		delete(c.cache, t)
	}
	c.memoryUsage = 0
}
