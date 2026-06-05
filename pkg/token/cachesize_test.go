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
	"testing"
	"unsafe"
)

func Test_getMapAllocatedSize(t *testing.T) {
	slotSize := int64(unsafe.Sizeof(CacheKey{})) + 16
	groupDataSize := int64(8) + int64(8)*slotSize

	// computeExpectedSize computes the expected allocated size for a map with the given hint.
	// swissmap: maxAvgGroupLoad=7, MapGroupSlots=8, maxTableCapacity=1024
	computeExpectedSize := func(hint int) int64 {
		if hint <= 8 {
			// Small map: single group, no table/directory overhead
			return groupDataSize
		}

		// Compute required capacity (power of 2, minimum 8)
		// growthLeft = (capacity * maxAvgGroupLoad) / MapGroupSlots
		// We need growthLeft >= hint, so capacity >= hint * 8 / 7
		capacity := 8
		for (capacity*7)/8 < hint {
			capacity *= 2
		}

		numGroups := capacity / 8
		tableSize := int64(unsafe.Sizeof(swissTable{})) + int64(numGroups)*groupDataSize

		if capacity <= 1024 {
			// Single table, directory length = 1
			dirSize := int64(1) * int64(unsafe.Sizeof(uintptr(0)))
			return dirSize + tableSize
		}

		// Multiple tables: each table has maxTableCapacity=1024, numGroups=128
		numTables := capacity / 1024
		singleTableSize := int64(unsafe.Sizeof(swissTable{})) + int64(1024/8)*groupDataSize
		dirLen := numTables
		dirSize := int64(dirLen) * int64(unsafe.Sizeof(uintptr(0)))
		return dirSize + singleTableSize*int64(numTables)
	}

	smallMap := make(map[CacheKey]Token)
	smallMap[CacheKey{Domain: "d", Role: "r"}] = &AccessToken{}

	tests := []struct {
		name     string
		c        map[CacheKey]Token
		wantSize int64
	}{
		{
			name:     "empty map",
			c:        make(map[CacheKey]Token, 0),
			wantSize: 0, // no allocation until first insert
		},
		{
			name:     "hint 8 (no allocation)",
			c:        make(map[CacheKey]Token, 8),
			wantSize: 0, // hint <= MapGroupSlots: lazy allocation
		},
		{
			name:     "small map with entry",
			c:        smallMap,
			wantSize: groupDataSize, // single group, no table/directory
		},
		{
			name:     "hint 1000",
			c:        make(map[CacheKey]Token, 1000),
			wantSize: computeExpectedSize(1000),
		},
		{
			name:     "hint 10000",
			c:        make(map[CacheKey]Token, 10000),
			wantSize: computeExpectedSize(10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSize := getMapAllocatedSize(tt.c)
			if gotSize != tt.wantSize {
				t.Errorf("getMapAllocatedSize() = %v, want %v", gotSize, tt.wantSize)
			}
		})
	}
}
