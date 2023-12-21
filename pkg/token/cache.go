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

func sizeofString(s string) uint {
	// size of string struct + number of bytes in string
	return uint(unsafe.Sizeof(s)) + uint(len(s))
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
	// structSize := uint(unsafe.Sizeof(k)) // should equal to the following sizes + sum of all strings' length
	domainSize := sizeofString(k.Domain)
	maxExpSize := uint(unsafe.Sizeof(k.MaxExpiry))
	minExpSize := uint(unsafe.Sizeof(k.MinExpiry))
	pfpSize := sizeofString(k.ProxyForPrincipal)
	roleSize := sizeofString(k.Role)
	// log.Debugf("👾👾👾CacheKey[%+v], structSize[%d]; domainSize[%d], maxExpSize[%d], minExpSize[%d], pfpSize[%d], roleSize[%d]\n", k, structSize, domainSize, maxExpSize, minExpSize, pfpSize, roleSize)
	return domainSize + pfpSize + maxExpSize + minExpSize + roleSize
}

type LockedTokenCache struct {
	cache map[CacheKey]Token
	lock  sync.RWMutex
	// memoryUsage is the number of bytes used by the cache entries. Usage of the cache map is counted.
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
		oldTokenSize := oldToken.Size()
		c.memoryUsage += int64(tokenSize) - int64(oldTokenSize)
	} else {
		keySize := k.Size()
		c.memoryUsage += int64(keySize + tokenSize)
	}
	// log.Debugf("👾👾👾New entry added to TokenCache, latest totalSize[%d], added keySize[%d], added tokenSize[%d]\n", c.Size(), keySize, tokenSize)
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
	// structSize := uint(unsafe.Sizeof(*c))     // should equal to the following sizes
	cacheSize := uint(unsafe.Sizeof(c.cache)) // not exact, there are hidden variables in map
	lockSize := uint(unsafe.Sizeof(c.lock))   // not exact, there are hidden variables in sync.RWMutex
	memSize := uint(unsafe.Sizeof(c.memoryUsage))
	// log.Debugf("👾👾👾LockedTokenCache[%+v], structSize[%d]; cacheSize[%d], lockSize[%d], memoryUsageSize[%d]\n", c, structSize, cacheSize, lockSize, memSize)
	return int64(cacheSize+lockSize+memSize) + c.memoryUsage
}

func (c *LockedTokenCache) Len() int {
	return len(c.cache)
}

func (c *LockedTokenCache) Clear() {
	for t := range c.cache {
		delete(c.cache, t)
	}
}
