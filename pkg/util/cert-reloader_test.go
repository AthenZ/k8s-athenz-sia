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
	"reflect"
	"testing"
)

func TestNewCertReloader(t *testing.T) {
	type args struct {
		config ReloadConfig
	}
	tests := []struct {
		name    string
		args    args
		want    *CertReloader
		wantErr bool
	}{
		{
			name: "Test NewCertReloader error in init mode",
			args: args{
				config: ReloadConfig{
					CertFile: "cert.pem",
					KeyFile:  "key.pem",
					Init:     true,
				},
			},
			want:    nil, // TODO: fixme
			wantErr: true,
		},
		{
			name: "Test NewCertReloader error in non-init mode",
			args: args{
				config: ReloadConfig{
					CertFile: "cert.pem",
					KeyFile:  "key.pem",
					Init:     false,
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCertReloader(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertReloader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCertReloader() = %v, want %v", got, tt.want)
			}
		})
	}
}
