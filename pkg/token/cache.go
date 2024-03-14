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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/prometheus/client_golang/prometheus"
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

// UniqueId returns a unique id of this token,
// ensuring that the id stays unique with Athenz naming rules.
// Athenz domain naming rule: "[a-zA-Z0-9_][a-zA-Z0-9_-]*")
// Athenz role naming rule: "[a-zA-Z0-9_][a-zA-Z0-9_-]*"
// and therefore delimiter "|" is used to separate domain and role for uniqueness.
func (k CacheKey) UniqueId(tokenType string) string {
	d := "|" // delimiter; using not allowed character for domain/role
	return strings.Join([]string{tokenType, k.Domain, k.Role, strconv.Itoa(k.MaxExpiry), strconv.Itoa(k.MinExpiry), k.ProxyForPrincipal}, d)
}

// String returns CacheKey's information in a string format, usually for logging purpose.
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

	// tokenType is the type of token stored in the cache.
	tokenType string
}

func NewLockedTokenCache(tokenType string) *LockedTokenCache {
	return &LockedTokenCache{
		cache:       make(map[CacheKey]Token),
		memoryUsage: 0,
		tokenType:   tokenType,
	}
}

func (c *LockedTokenCache) Store(k CacheKey, t Token) {
	c.lock.Lock()
	defer c.lock.Unlock()
	oldToken, ok := c.cache[k]
	c.cache[k] = t

	// update cache memory usage
	if ok {
		// convert unsigned to signed to allow negative result
		c.memoryUsage += int64(t.Size()) - int64(oldToken.Size())
	} else {
		c.memoryUsage += int64(t.Size() + k.Size())
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
		// TODO: reset metrics on delete

	}
	c.memoryUsage = 0
}

var (
	tokenExpiresInMetric = "token_expires_in_seconds"
	tokenExpiresInHelp   = "Indicates remaining time until the token expires"
)

func (c *LockedTokenCache) Describe(ch chan<- *prometheus.Desc) {
	labelKeys := []string{"domain", "role"}
	ch <- prometheus.NewDesc(tokenExpiresInMetric, tokenExpiresInHelp, labelKeys, prometheus.Labels{
		"type": c.tokenType,
	})
}

func (c *LockedTokenCache) Collect(ch chan<- prometheus.Metric) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// prepare k8s env if exists
	k8sNamespace := os.Getenv("NAMESPACE")
	k8sPodName := os.Getenv("POD_NAME")

	for k, t := range c.cache {
		// skip placeholder token added during daemon creation
		if t.Raw() == "" {
			continue
		}

		labelKeys := []string{"domain", "role"}
		labelValues := []string{k.Domain, k.Role}
		if k.ProxyForPrincipal != "" {
			labelKeys = append(labelKeys, "proxy_for_principal")
			labelValues = append(labelValues, k.ProxyForPrincipal)
		}
		if k.MinExpiry != 0 {
			labelKeys = append(labelKeys, "min_expiry")
			labelValues = append(labelValues, fmt.Sprintf("%d", k.MinExpiry))
		}
		if k.MaxExpiry != 0 {
			labelKeys = append(labelKeys, "max_expiry")
			labelValues = append(labelValues, fmt.Sprintf("%d", k.MaxExpiry))
		}
		// only appends when it is k8s env. sia in non-k8s won't have these metrics key
		if k8sNamespace != "" {
			labelKeys = append(labelKeys, "k8s_namespace")
			labelValues = append(labelValues, k8sNamespace)
		}
		// only appends when it is k8s env. sia in non-k8s won't have these metrics key
		if k8sPodName != "" {
			labelKeys = append(labelKeys, "k8s_pod")
			labelValues = append(labelValues, k8sPodName)
		}
		metric, err := prometheus.NewConstMetric(
			prometheus.NewDesc(tokenExpiresInMetric, tokenExpiresInHelp, labelKeys, prometheus.Labels{
				"type": c.tokenType,
			}),
			prometheus.GaugeValue,
			float64(time.Until(time.Unix(t.Expiry(), 0)).Seconds()),
			labelValues...,
		)
		if err != nil {
			log.Errorf("Failed to create metric: %v", err)
			continue
		}
		ch <- metric
	}
}
