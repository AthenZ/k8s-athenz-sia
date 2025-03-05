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

package util

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	. "github.com/onsi/gomega"
)

func TestCreateDirectory(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		before  func(path string)
	}{
		{
			name: "Test create directory",
			args: args{
				path: "test_1",
			},
			wantErr: false,
		},
		{
			name: "Test create sub-directory",
			args: args{
				path: "test_2/sub",
			},
			wantErr: false,
		},
		{
			name: "Test directory already exist",
			args: args{
				path: "test_3",
			},
			wantErr: false,
			before: func(path string) {
				err := os.MkdirAll(path, 0755)
				if err != nil {
					t.Fatalf("unable to create directory: %v", err)
				}
			},
		},
		// TODO: this test case should pass
		// {
		// 	name: "Test create directory error",
		// 	args: args{
		// 		path: "test_4",
		// 	},
		// 	wantErr: true,
		// 	before: func(path string) {
		// 		file, err := os.Create(path)
		// 		defer file.Close()
		// 		if err != nil {
		// 			t.Fatalf("unable to create file: %v", err)
		// 		}
		// 	},
		// },
	}

	log.InitLogger("", "debug", false) // init logger
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			testPath := path.Join(t.TempDir(), tt.args.path)
			if tt.before != nil {
				tt.before(testPath)
			}
			err := CreateDirectory(path.Join(testPath, "file.txt"))
			entries, _ := os.ReadDir(filepath.Dir(testPath))
			t.Logf("Entries: %v", entries)
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(testPath).To(BeADirectory())
			}
		})
	}
}
