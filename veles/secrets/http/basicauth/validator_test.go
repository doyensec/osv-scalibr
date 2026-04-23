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

package basicauth_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/http/basicauth"
)

// setupMockServer creates an httptest.Server that verifies the incoming HTTP request
// matches the expected method and path, and returns the appropriate differential status code.
func setupMockServer(t *testing.T, expectedMethod, expectedPath, username, password string, unauthStatus, authStatus int) *httptest.Server {
	t.Helper() // Marks this as a test helper function so failure logs point to the actual test case line

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expectedMethod {
			t.Errorf("Expected method %s, got %s", expectedMethod, r.Method)
		}

		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(unauthStatus)
			return
		}

		// Ensure the Authorization header is actually correct if it was sent
		expectedPayload := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		if !strings.HasSuffix(authHeader, expectedPayload) {
			t.Errorf("Expected Auth header to end with %s, got %s", expectedPayload, authHeader)
		}

		w.WriteHeader(authStatus)
	}))
}

func TestValidator_Validate(t *testing.T) {
	tests := []struct {
		name             string
		credentials      basicauth.Credentials // TargetURL will be dynamically overwritten with the mock server URL
		unauthStatusCode int                   // Status the server should return when no Auth header is present
		authStatusCode   int                   // Status the server should return when the Auth header is present
		expectedMethod   string                // To verify method downgrading
		expectedPath     string                // To verify path appending
		expectedStatus   veles.ValidationStatus
		wantErr          error
	}{
		{
			name: "valid_credentials_unauthorized_to_ok",
			credentials: basicauth.Credentials{
				Username: "admin",
				Password: "password123",
				Method:   http.MethodGet,
				Path:     "/api/v1/data",
			},
			unauthStatusCode: http.StatusUnauthorized,
			authStatusCode:   http.StatusOK,
			expectedMethod:   http.MethodGet,
			expectedPath:     "/api/v1/data",
			expectedStatus:   veles.ValidationValid,
		},
		{
			name: "valid_credentials_unauthorized_to_forbidden",
			credentials: basicauth.Credentials{
				Username: "user",
				Password: "password123",
			},
			unauthStatusCode: http.StatusUnauthorized,
			authStatusCode:   http.StatusForbidden,
			expectedMethod:   http.MethodGet,
			expectedPath:     "/", // Default path when not specified
			expectedStatus:   veles.ValidationValid,
		},
		{
			name: "invalid_credentials_stays_unauthorized",
			credentials: basicauth.Credentials{
				Username: "admin",
				Password: "wrongpassword",
			},
			unauthStatusCode: http.StatusUnauthorized,
			authStatusCode:   http.StatusUnauthorized,
			expectedMethod:   http.MethodGet,
			expectedPath:     "/",
			expectedStatus:   veles.ValidationFailed,
			wantErr:          cmpopts.AnyError,
		},
		{
			name: "endpoint_ignores_auth_is_public",
			credentials: basicauth.Credentials{
				Username: "admin",
				Password: "password123",
			},
			unauthStatusCode: http.StatusOK, // Endpoint returns 200 even without credentials
			authStatusCode:   http.StatusOK,
			expectedMethod:   http.MethodGet,
			expectedPath:     "/",
			expectedStatus:   veles.ValidationFailed,
			wantErr:          cmpopts.AnyError,
		},
		{
			name: "method_downgrade_post_to_get",
			credentials: basicauth.Credentials{
				Username: "admin",
				Password: "password123",
				Method:   http.MethodPost, // Should be downgraded to GET
			},
			unauthStatusCode: http.StatusUnauthorized,
			authStatusCode:   http.StatusOK,
			expectedMethod:   http.MethodGet,
			expectedPath:     "/",
			expectedStatus:   veles.ValidationValid,
		},
		{
			name: "server_error_on_auth",
			credentials: basicauth.Credentials{
				Username: "admin",
				Password: "password123",
			},
			unauthStatusCode: http.StatusUnauthorized,
			authStatusCode:   http.StatusInternalServerError,
			expectedMethod:   http.MethodGet,
			expectedPath:     "/",
			expectedStatus:   veles.ValidationFailed,
			wantErr:          cmpopts.AnyError,
		},
		{
			name: "missing_target_url",
			credentials: basicauth.Credentials{
				TargetURL: "", // Won't make HTTP request
			},
			expectedStatus: veles.ValidationFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Spin up the mock server using our helper
			server := setupMockServer(
				t,
				test.expectedMethod,
				test.expectedPath,
				test.credentials.Username,
				test.credentials.Password,
				test.unauthStatusCode,
				test.authStatusCode,
			)
			defer server.Close()

			// Wire up the validator
			validator := basicauth.NewValidator()
			validator.Client = server.Client()

			// Inject the mock server URL into the credentials (unless testing the empty URL case)
			creds := test.credentials
			if creds.TargetURL != "" || test.name != "missing_target_url" {
				creds.TargetURL = server.URL
			}

			// Execute
			status, err := validator.Validate(t.Context(), creds)

			// Assertions
			if diff := cmp.Diff(test.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Validate() error mismatch (-want +got):\n%s", diff)
			}

			if status != test.expectedStatus {
				t.Errorf("Expected status %v, got %v", test.expectedStatus, status)
			}
		})
	}
}

func TestValidator_InvalidURL(t *testing.T) {
	validator := basicauth.NewValidator()

	// Provide a malformed URL that fails HTTP request construction
	creds := basicauth.Credentials{
		TargetURL: string([]byte{0x7f}), // Invalid control character in URL
		Username:  "admin",
		Password:  "password",
	}

	status, err := validator.Validate(t.Context(), creds)

	if err == nil {
		t.Fatal("Expected error for invalid URL, got nil")
	}
	if status != veles.ValidationFailed {
		t.Errorf("Expected ValidationFailed status, got %v", status)
	}
}

func TestValidator_NetworkError(t *testing.T) {
	// Use a URL that will cause an immediate network error (nothing listening)
	validator := basicauth.NewValidator()
	creds := basicauth.Credentials{
		TargetURL: "http://localhost:1",
		Username:  "admin",
		Password:  "password",
	}

	status, err := validator.Validate(t.Context(), creds)

	if err == nil {
		t.Fatal("Expected network error, got nil")
	}
	if status != veles.ValidationFailed {
		t.Errorf("Expected ValidationFailed status, got %v", status)
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler never responds, ensuring we test context cancellation on the client side
		select {}
	}))
	defer server.Close()

	validator := basicauth.NewValidator()
	validator.Client = server.Client()

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately before doing the request

	creds := basicauth.Credentials{
		TargetURL: server.URL,
		Username:  "admin",
		Password:  "password",
	}

	status, err := validator.Validate(ctx, creds)

	if err == nil {
		t.Fatal("Expected context cancellation error, got nil")
	}
	if status != veles.ValidationFailed {
		t.Errorf("Expected ValidationFailed status, got %v", status)
	}
}
