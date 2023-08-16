// Copyright 2023 Yahoo Japan Corporation
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
)

type TokenCache interface {
	Store(k CacheKey, t Token)
	Load(k CacheKey) Token
	Range(func(k CacheKey, t Token) error) error
	Keys() []CacheKey
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

type LockedTokenCache struct {
	cache map[CacheKey]Token
	lock  sync.RWMutex
}

func NewLockedTokenCache() *LockedTokenCache {
	return &LockedTokenCache{cache: make(map[CacheKey]Token)}
}

func (c *LockedTokenCache) Store(k CacheKey, t Token) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.cache[k] = t
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
