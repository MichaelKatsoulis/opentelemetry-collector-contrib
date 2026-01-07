// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awslambdareceiver

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.opentelemetry.io/collector/confmap/xconfmap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awslambdareceiver/internal/metadata"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)

	tests := []struct {
		name              string
		componentIDToLoad component.ID
		expected          component.Config
	}{
		{
			name:              "Config with both S3 and CloudWatch encoding",
			componentIDToLoad: component.NewIDWithName(metadata.Type, "awslogs_encoding"),
			expected: &Config{
				S3: S3Config{
					Encoding: "awslogs_encoding",
				},
				CloudWatch: sharedConfig{
					Encoding: "awslogs_encoding",
				},
			},
		},
		{
			name:              "Config with both S3 config only",
			componentIDToLoad: component.NewIDWithName(metadata.Type, "json_log_encoding"),
			expected: &Config{
				S3: S3Config{
					Encoding: "json_log_encoding",
				},
				CloudWatch: sharedConfig{},
			},
		},
		{
			name:              "Config with empty encoding",
			componentIDToLoad: component.NewIDWithName(metadata.Type, "empty_encoding"),
			expected: &Config{
				S3:         S3Config{},
				CloudWatch: sharedConfig{},
			},
		},
		{
			name:              "Config with failure bucket ARN",
			componentIDToLoad: component.NewIDWithName(metadata.Type, "with_failure_arn"),
			expected: &Config{
				S3:               S3Config{},
				CloudWatch:       sharedConfig{},
				FailureBucketARN: "arn:aws:s3:::example",
			},
		},
	}

	for _, tt := range tests {
		name := strings.ReplaceAll(tt.componentIDToLoad.String(), "/", "_")
		t.Run(name, func(t *testing.T) {
			factory := NewFactory()
			cfg := factory.CreateDefaultConfig()

			sub, err := cm.Sub(tt.componentIDToLoad.String())
			require.NoError(t, err)
			require.NoError(t, sub.Unmarshal(cfg))

			err = xconfmap.Validate(cfg)
			require.NoError(t, err)
			require.Equal(t, tt.expected, cfg)
		})
	}
}

func TestS3ConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  S3Config
		wantErr string
	}{
		{
			name:    "empty config is valid",
			config:  S3Config{},
			wantErr: "",
		},
		{
			name: "single encoding is valid",
			config: S3Config{
				Encoding: "awslogs_encoding",
			},
			wantErr: "",
		},
		{
			name: "formats with known names and default prefixes is valid",
			config: S3Config{
				Formats: []S3Format{
					{Name: "vpcflow", Encoding: "awslogs_encoding/vpcflow"},
					{Name: "cloudtrail", Encoding: "awslogs_encoding/cloudtrail"},
				},
			},
			wantErr: "",
		},
		{
			name: "formats with custom path pattern is valid",
			config: S3Config{
				Formats: []S3Format{
					{Name: "custom", Encoding: "my_encoding", PathPattern: "custom-logs/"},
				},
			},
			wantErr: "",
		},
		{
			name: "formats with raw passthrough (no encoding) is valid",
			config: S3Config{
				Formats: []S3Format{
					{Name: "raw", PathPattern: "raw-logs/"},
				},
			},
			wantErr: "",
		},
		{
			name: "catch-all pattern with * is valid",
			config: S3Config{
				Formats: []S3Format{
					{Name: "catchall", PathPattern: "*"},
				},
			},
			wantErr: "",
		},
		{
			name: "encoding and formats are mutually exclusive",
			config: S3Config{
				Encoding: "awslogs_encoding",
				Formats: []S3Format{
					{Name: "vpcflow"},
				},
			},
			wantErr: "'encoding' and 'formats' are mutually exclusive",
		},
		{
			name: "format without name is invalid",
			config: S3Config{
				Formats: []S3Format{
					{Encoding: "awslogs_encoding", PathPattern: "logs/"},
				},
			},
			wantErr: "'name' is required",
		},
		{
			name: "unknown format without path pattern is invalid",
			config: S3Config{
				Formats: []S3Format{
					{Name: "custom_format", Encoding: "my_encoding"},
				},
			},
			wantErr: "'path_pattern' is required for format \"custom_format\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestS3FormatResolvePathPattern(t *testing.T) {
	tests := []struct {
		name     string
		format   S3Format
		expected string
	}{
		{
			name:     "known format uses default path pattern",
			format:   S3Format{Name: "vpcflow"},
			expected: "vpcflowlogs/",
		},
		{
			name:     "known format uses default path pattern - cloudtrail",
			format:   S3Format{Name: "cloudtrail"},
			expected: "CloudTrail/",
		},
		{
			name:     "custom path pattern overrides default",
			format:   S3Format{Name: "vpcflow", PathPattern: "custom-vpc/"},
			expected: "custom-vpc/",
		},
		{
			name:     "unknown format with custom path pattern",
			format:   S3Format{Name: "custom", PathPattern: "my-logs/"},
			expected: "my-logs/",
		},
		{
			name:     "unknown format without path pattern returns empty",
			format:   S3Format{Name: "unknown"},
			expected: "",
		},
		{
			name:     "catch-all pattern * resolves to empty string",
			format:   S3Format{Name: "catchall", PathPattern: "*"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.format.ResolvePathPattern()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestS3ConfigSortedFormats(t *testing.T) {
	tests := []struct {
		name          string
		config        S3Config
		expectedOrder []string // expected order of format names
	}{
		{
			name:          "empty formats returns nil",
			config:        S3Config{},
			expectedOrder: nil,
		},
		{
			name: "single format unchanged",
			config: S3Config{
				Formats: []S3Format{
					{Name: "vpcflow"},
				},
			},
			expectedOrder: []string{"vpcflow"},
		},
		{
			name: "catch-all pattern * moved to last",
			config: S3Config{
				Formats: []S3Format{
					{Name: "catchall", PathPattern: "*"},
					{Name: "vpcflow"},
					{Name: "cloudtrail"},
				},
			},
			expectedOrder: []string{"vpcflow", "cloudtrail", "catchall"},
		},
		{
			name: "longer patterns come first",
			config: S3Config{
				Formats: []S3Format{
					{Name: "short", PathPattern: "a/"},
					{Name: "long", PathPattern: "very/long/path/"},
					{Name: "medium", PathPattern: "medium/"},
				},
			},
			expectedOrder: []string{"long", "medium", "short"},
		},
		{
			name: "mixed catch-all and specific patterns",
			config: S3Config{
				Formats: []S3Format{
					{Name: "catchall", PathPattern: "*"},
					{Name: "vpcflow"},                             // default: "vpcflowlogs/"
					{Name: "custom", PathPattern: "custom-logs/"}, // shorter than vpcflowlogs/
				},
			},
			expectedOrder: []string{"vpcflow", "custom", "catchall"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sorted := tt.config.SortedFormats()

			if tt.expectedOrder == nil {
				assert.Nil(t, sorted)
				return
			}

			var actualOrder []string
			for _, f := range sorted {
				actualOrder = append(actualOrder, f.Name)
			}
			assert.Equal(t, tt.expectedOrder, actualOrder)
		})
	}
}
