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
	"math"
	"testing"
	"unsafe"
)

func Test_getMapBucketLenAndSize(t *testing.T) {
	type args struct {
		c map[CacheKey]Token
	}
	b := unsafe.Sizeof(bmap{})
	computeRequiredBuckets := func(l float64) int64 {
		// ensure number of buckets in power of 2 > entries size / load factor (i.e. 6.5)
		// e.g. 1000 entries /6.5 = 153.8 < 2^8 = 256 buckets
		// https://github.com/golang/go/blob/2184a394777ccc9ce9625932b2ad773e6e626be0/src/runtime/map.go#L73C3-L73C3
		return 1 << uint(math.Ceil(math.Log2(l/13.0*2.0)))
	}
	tests := []struct {
		name           string
		args           args
		wantBucketLen  int
		wantBucketSize int64
	}{
		{
			name: "empty map",
			args: args{
				c: make(map[CacheKey]Token, 0),
			},
			wantBucketLen:  1,
			wantBucketSize: int64(b),
		},
		{
			name: "1000 map",
			args: args{
				c: make(map[CacheKey]Token, 1000),
			},
			wantBucketLen:  256,
			wantBucketSize: int64(b) * computeRequiredBuckets(1000),
		},
		{
			name: "10000 map",
			args: args{
				c: make(map[CacheKey]Token, 10000),
			},
			wantBucketLen:  2048,
			wantBucketSize: int64(b) * computeRequiredBuckets(10000),
		},
		// will fail as there are special handling logic when entry size is large, the simple formula in computeRequiredBuckets() does not apply
		// special handling logic: https://github.com/golang/go/blob/2184a394777ccc9ce9625932b2ad773e6e626be0/src/runtime/map.go#L346
		// {
		// 	name: "100000 map",
		// 	args: args{
		// 		c: make(map[CacheKey]Token, 100000),
		// 	},
		// 	wantBucketLen:  16384,
		// 	wantBucketSize: int64(b) * computeRequiredBuckets(100000),
		// },
		{
			name: "150000 map",
			args: args{
				c: make(map[CacheKey]Token, 150000),
			},
			wantBucketLen:  32768,
			wantBucketSize: int64(b) * computeRequiredBuckets(150000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBucketLen, gotBucketSize := getMapBucketLenAndSize(tt.args.c)
			if gotBucketLen != tt.wantBucketLen {
				t.Errorf("getMapBucketLenAndSize() gotBucketLen = %v, want %v", gotBucketLen, tt.wantBucketLen)
			}
			if gotBucketSize != tt.wantBucketSize {
				t.Errorf("getMapBucketLenAndSize() gotBucketSize = %v, want %v", gotBucketSize, tt.wantBucketSize)
			}
		})
	}
}
