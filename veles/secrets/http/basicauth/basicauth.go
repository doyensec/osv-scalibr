// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package basicauth contains the logic to extract basic auth headers
//
// ref: https://www.rfc-editor.org/rfc/rfc7617
package basicauth

// Credentials contains the extracted target URL/Path and decoded basic auth payload.
type Credentials struct {
	Metadata *Metadata
	Username string
	Password string
}

// Metadata contains info on how credentials might be validated
type Metadata struct {
	TargetURL string
	Path      string
	Method    string
}
