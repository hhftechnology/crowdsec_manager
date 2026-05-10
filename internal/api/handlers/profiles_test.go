package handlers

import (
	"encoding/base64"
	"errors"
	"testing"

	"crowdsec-manager/internal/models"
)

func TestDecodeProfileContent(t *testing.T) {
	t.Parallel()

	content := "filters:\n  - Alert.Remediation == true && Alert.GetScope() == \"Ip\"\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	tests := []struct {
		name    string
		req     models.ProfileRequest
		want    string
		wantErr error
	}{
		{
			name: "legacy plain content",
			req: models.ProfileRequest{
				Content: content,
			},
			want: content,
		},
		{
			name: "base64 content",
			req: models.ProfileRequest{
				ContentB64: encoded,
				Encoding:   "base64",
			},
			want: content,
		},
		{
			name: "base64 content without explicit encoding",
			req: models.ProfileRequest{
				ContentB64: encoded,
			},
			want: content,
		},
		{
			name: "invalid base64",
			req: models.ProfileRequest{
				ContentB64: "not-valid-base64",
				Encoding:   "base64",
			},
			wantErr: base64.CorruptInputError(3),
		},
		{
			name:    "missing content",
			req:     models.ProfileRequest{},
			wantErr: errProfileContentMissing,
		},
		{
			name: "unsupported encoding",
			req: models.ProfileRequest{
				ContentB64: encoded,
				Encoding:   "gzip",
			},
			wantErr: errProfileEncodingUnsupported,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeProfileContent(tt.req)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("decodeProfileContent() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeProfileContent() unexpected error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("decodeProfileContent() = %q, want %q", got, tt.want)
			}
		})
	}
}
