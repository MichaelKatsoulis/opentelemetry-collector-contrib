// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awslambdareceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awslambdareceiver"

import (
	"fmt"
	"strings"

	"go.opentelemetry.io/collector/pdata/plog"
)

// logsEncodingRouter routes S3 object keys to the appropriate logs unmarshaler
// based on path pattern matching.
type logsEncodingRouter struct {
	// formats sorted by specificity (longer patterns first, catch-all last)
	formats []S3Format
	// encoders maps format name to unmarshaler
	encoders map[string]unmarshalFunc[plog.Logs]
	// defaultUnmarshaler is used for raw passthrough (formats with no encoding)
	defaultUnmarshaler unmarshalFunc[plog.Logs]
}

// newLogsEncodingRouter creates a new router with the given formats and encoders.
func newLogsEncodingRouter(
	formats []S3Format,
	encoders map[string]unmarshalFunc[plog.Logs],
	defaultUnmarshaler unmarshalFunc[plog.Logs],
) *logsEncodingRouter {
	return &logsEncodingRouter{
		formats:            formats,
		encoders:           encoders,
		defaultUnmarshaler: defaultUnmarshaler,
	}
}

// GetUnmarshaler returns the appropriate unmarshaler for the given S3 object key.
// It matches the object key against configured path patterns and returns the
// corresponding unmarshaler. If no pattern matches, it returns an error.
func (r *logsEncodingRouter) GetUnmarshaler(objectKey string) (unmarshalFunc[plog.Logs], string, error) {
	for _, format := range r.formats {
		pattern := format.ResolvePathPattern()

		// Empty pattern (from "*") matches everything
		if pattern == "" || strings.Contains(objectKey, pattern) {
			// If no encoding specified, use default (raw passthrough)
			if format.Encoding == "" {
				return r.defaultUnmarshaler, format.Name, nil
			}

			unmarshaler, ok := r.encoders[format.Name]
			if !ok {
				return nil, "", fmt.Errorf("no encoder found for format %q", format.Name)
			}
			return unmarshaler, format.Name, nil
		}
	}

	return nil, "", fmt.Errorf("no format matches S3 object key: %s", objectKey)
}
