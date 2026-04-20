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

package basicauth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
)

// Validator implements the veles.Validator interface for Basic Auth credentials.
type Validator struct {
	Client *http.Client
}

// Ensure Validator implements the interface at compile-time.
var _ veles.Validator[Credentials] = (*Validator)(nil)

// NewValidator creates a new active validator for Basic Auth credentials.
func NewValidator() *Validator {
	return &Validator{
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// Validate checks if the provided secret is active using differential HTTP requests.
func (v *Validator) Validate(ctx context.Context, creds Credentials) (veles.ValidationStatus, error) {
	if creds.TargetURL == "" {
		// Without a target URL, we cannot attempt validation.
		return veles.ValidationFailed, nil
	}

	// 1. Normalize the Target URL & Method
	target := creds.TargetURL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	if creds.Path != "" && creds.Path != "/" && !strings.Contains(target, creds.Path) {
		target = strings.TrimRight(target, "/") + creds.Path
	}

	method := strings.ToUpper(creds.Method)
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		// Downgrade any destructive or unknown method to GET.
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed building the unauthenticated request: %w", err)
	}

	unauthResp, err := v.Client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unauthenticated request failed: %w", err)
	}
	unauthStatus := unauthResp.StatusCode
	unauthResp.Body.Close()

	// If the endpoint doesn't care about auth (e.g., it's public and returns 200 OK anyway),
	// we cannot reliably prove these specific credentials are valid.
	if unauthStatus != http.StatusUnauthorized && unauthStatus != http.StatusForbidden {
		return veles.ValidationFailed, fmt.Errorf("endpoint is public or ignores auth (returned %d)", unauthStatus)
	}

	req.SetBasicAuth(creds.Username, creds.Password)
	authResp, err := v.Client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("authenticated request failed: %w", err)
	}
	authStatus := authResp.StatusCode
	authResp.Body.Close()

	// The status changed! This is our strong signal.
	if authStatus >= 200 && authStatus < 400 {
		return veles.ValidationValid, nil
	}

	// e.g., 401 -> 403. Authentication succeeded, but Authorization failed.
	if authStatus == http.StatusForbidden && unauthStatus == http.StatusUnauthorized {
		return veles.ValidationValid, nil
	}

	// Any other weird combination (e.g., 401 -> 500) goes to failed
	return veles.ValidationFailed, fmt.Errorf("unexpected authenticated response status: %d", authStatus)
}
