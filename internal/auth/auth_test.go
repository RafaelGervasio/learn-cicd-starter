package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		header      http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "Valid API Key",
			header:      http.Header{"Authorization": []string{"ApiKey 12345"}},
			expectedKey: "12345",
			expectedErr: nil,
		},
		{
			name:        "No Authorization Header",
			header:      http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization Header - Missing Key",
			header:      http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			name:        "Malformed Authorization Header - Incorrect Prefix",
			header:      http.Header{"Authorization": []string{"Bearer 12345"}},
			expectedKey: "",
			expectedErr: ErrMalformedAuthHeader,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualKey, actualErr := GetAPIKey(tc.header)

			if actualKey != tc.expectedKey || !errors.Is(actualErr, tc.expectedErr) {
				t.Errorf("Test %s failed: GetAPIKey(%v); expected (%s, %v); got (%s, %v)",
					tc.name, tc.header, tc.expectedKey, tc.expectedErr, actualKey, actualErr)
			}
		})
	}
}
