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

import "unsafe"

// https://github.com/golang/go/blob/2184a394777ccc9ce9625932b2ad773e6e626be0/src/runtime/map.go#L117-L131
type hmap struct {
	// Note: the format of the hmap is also encoded in cmd/compile/internal/reflectdata/reflect.go.
	// Make sure this stays in sync with the compiler's definition.
	count     int // # live cells == size of map.  Must be first (used by len() builtin)
	flags     uint8
	B         uint8  // log_2 of # of buckets (can hold up to loadFactor * 2^B items)
	noverflow uint16 // approximate number of overflow buckets; see incrnoverflow for details
	hash0     uint32 // hash seed

	buckets    unsafe.Pointer // array of 2^B Buckets. may be nil if count==0.
	oldbuckets unsafe.Pointer // previous bucket array of half the size, non-nil only when growing
	nevacuate  uintptr        // progress counter for evacuation (buckets less than this have been evacuated)

	// unused, comment out for simplicity
	// extra *mapextra // optional fields
}

// https://github.com/golang/go/blob/2184a394777ccc9ce9625932b2ad773e6e626be0/src/runtime/map.go#L67
const bucketCnt = 8

// https://github.com/golang/go/blob/2184a394777ccc9ce9625932b2ad773e6e626be0/src/runtime/map.go#L150-L161
type bmap struct {
	tophash [bucketCnt]uint8

	// dynamically created
	keys     [bucketCnt]CacheKey
	values   [bucketCnt]Token
	overflow *bmap
}

// emptyInterface is the internally representation of interface{}.
type emptyInterface struct {
	_type unsafe.Pointer
	value unsafe.Pointer
}

// extractHmap extracts the underlining hmap struct pointer from a map unsafely.
func extractHmap(m interface{}) *hmap {
	ei := (*emptyInterface)(unsafe.Pointer(&m))
	return (*hmap)(ei.value)
}

// getMapBucketLenAndSize returns the bucket length and size of a map.
func getMapBucketLenAndSize(c map[CacheKey]Token) (int, int64) {
	h := extractHmap(c)
	bucketLen := 1 << h.B

	singleBucketSize := int64(unsafe.Sizeof(bmap{}))

	return bucketLen, singleBucketSize * int64(bucketLen)
}
