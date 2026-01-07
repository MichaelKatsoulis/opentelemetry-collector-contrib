// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awslambdareceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestLogsEncodingRouter_GetUnmarshaler(t *testing.T) {
	// Create mock unmarshalers
	vpcUnmarshaler := func(data []byte) (plog.Logs, error) { return plog.NewLogs(), nil }
	cloudtrailUnmarshaler := func(data []byte) (plog.Logs, error) { return plog.NewLogs(), nil }
	defaultUnmarshaler := func(data []byte) (plog.Logs, error) { return plog.NewLogs(), nil }

	tests := []struct {
		name           string
		formats        []S3Format
		encoders       map[string]unmarshalFunc[plog.Logs]
		objectKey      string
		expectedFormat string
		expectError    bool
	}{
		{
			name: "matches vpcflow pattern",
			formats: []S3Format{
				{Name: "vpcflow", Encoding: "awslogs_encoding/vpc"},
				{Name: "cloudtrail", Encoding: "awslogs_encoding/ct"},
			},
			encoders: map[string]unmarshalFunc[plog.Logs]{
				"vpcflow":    vpcUnmarshaler,
				"cloudtrail": cloudtrailUnmarshaler,
			},
			objectKey:      "AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/file.log.gz",
			expectedFormat: "vpcflow",
			expectError:    false,
		},
		{
			name: "matches cloudtrail pattern",
			formats: []S3Format{
				{Name: "vpcflow", Encoding: "awslogs_encoding/vpc"},
				{Name: "cloudtrail", Encoding: "awslogs_encoding/ct"},
			},
			encoders: map[string]unmarshalFunc[plog.Logs]{
				"vpcflow":    vpcUnmarshaler,
				"cloudtrail": cloudtrailUnmarshaler,
			},
			objectKey:      "AWSLogs/123456789012/CloudTrail/us-east-1/2024/01/15/file.json.gz",
			expectedFormat: "cloudtrail",
			expectError:    false,
		},
		{
			name: "catch-all pattern matches unmatched keys",
			formats: []S3Format{
				{Name: "vpcflow", Encoding: "awslogs_encoding/vpc"},
				{Name: "catchall", Encoding: "fallback_encoding", PathPattern: "*"},
			},
			encoders: map[string]unmarshalFunc[plog.Logs]{
				"vpcflow":  vpcUnmarshaler,
				"catchall": cloudtrailUnmarshaler,
			},
			objectKey:      "random/path/to/file.log",
			expectedFormat: "catchall",
			expectError:    false,
		},
		{
			name: "raw passthrough format (no encoding)",
			formats: []S3Format{
				{Name: "vpcflow", Encoding: "awslogs_encoding/vpc"},
				{Name: "raw", PathPattern: "raw-logs/"},
			},
			encoders: map[string]unmarshalFunc[plog.Logs]{
				"vpcflow": vpcUnmarshaler,
				// "raw" has no encoder - uses default
			},
			objectKey:      "raw-logs/file.txt",
			expectedFormat: "raw",
			expectError:    false,
		},
		{
			name: "no matching pattern returns error",
			formats: []S3Format{
				{Name: "vpcflow", Encoding: "awslogs_encoding/vpc"},
			},
			encoders: map[string]unmarshalFunc[plog.Logs]{
				"vpcflow": vpcUnmarshaler,
			},
			objectKey:   "completely/different/path/file.log",
			expectError: true,
		},
		{
			name: "custom path pattern",
			formats: []S3Format{
				{Name: "custom", Encoding: "custom_encoding", PathPattern: "my-custom-logs/"},
			},
			encoders: map[string]unmarshalFunc[plog.Logs]{
				"custom": vpcUnmarshaler,
			},
			objectKey:      "bucket/my-custom-logs/2024/file.log",
			expectedFormat: "custom",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newLogsEncodingRouter(tt.formats, tt.encoders, defaultUnmarshaler)

			unmarshaler, formatName, err := router.GetUnmarshaler(tt.objectKey)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, unmarshaler)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, unmarshaler)
				assert.Equal(t, tt.expectedFormat, formatName)
			}
		})
	}
}

func TestLogsEncodingRouter_PatternPriority(t *testing.T) {
	// Test that longer/more specific patterns are matched before shorter ones
	vpcUnmarshaler := func(data []byte) (plog.Logs, error) { return plog.NewLogs(), nil }
	catchallUnmarshaler := func(data []byte) (plog.Logs, error) { return plog.NewLogs(), nil }
	defaultUnmarshaler := func(data []byte) (plog.Logs, error) { return plog.NewLogs(), nil }

	// Formats should be pre-sorted by SortedFormats() - longer patterns first
	formats := []S3Format{
		{Name: "vpcflow"}, // default pattern: "vpcflowlogs/" (12 chars)
		{Name: "catchall", PathPattern: "*"},
	}

	encoders := map[string]unmarshalFunc[plog.Logs]{
		"vpcflow":  vpcUnmarshaler,
		"catchall": catchallUnmarshaler,
	}

	router := newLogsEncodingRouter(formats, encoders, defaultUnmarshaler)

	// VPC flow log should match vpcflow, not catchall
	_, formatName, err := router.GetUnmarshaler("AWSLogs/123/vpcflowlogs/file.log")
	require.NoError(t, err)
	assert.Equal(t, "vpcflow", formatName)

	// Random path should match catchall
	_, formatName, err = router.GetUnmarshaler("random/file.log")
	require.NoError(t, err)
	assert.Equal(t, "catchall", formatName)
}
