// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package awslambdareceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awslambdareceiver"

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"go.opentelemetry.io/collector/component"
)

const (
	s3ARNPrefix = "arn:aws:s3:::"

	// CatchAllPattern is a special pattern value that matches any S3 object key.
	// Use this for formats that should act as a fallback/catch-all.
	CatchAllPattern = "*"
)

// defaultPathPatterns maps known format names to their default S3 path patterns.
// These patterns are matched using substring search against the S3 object key.
var defaultPathPatterns = map[string]string{
	"vpcflow":         "vpcflowlogs/",
	"cloudtrail":      "CloudTrail/",
	"elbaccess":       "elasticloadbalancing/",
	"waf":             "WAFLogs/",
	"networkfirewall": "network-firewall/",
}

// S3Format defines a format entry for multi-format S3 log processing.
type S3Format struct {
	// Name identifies the format (used for logging and default path pattern lookup).
	Name string `mapstructure:"name"`

	// Encoding is the extension ID for decoding. If empty, content is passed through as-is (raw).
	Encoding string `mapstructure:"encoding"`

	// PathPattern is matched against the S3 object key using substring search.
	// If empty, uses default pattern for known format names.
	PathPattern string `mapstructure:"path_pattern"`
}

// S3Config defines configuration options for S3 Lambda trigger.
type S3Config struct {
	// Encoding defines the encoding to decode incoming S3 data (single-format mode).
	// This is mutually exclusive with Formats.
	Encoding string `mapstructure:"encoding"`

	// Formats defines multiple format entries for prefix-based routing (multi-format mode).
	// This is mutually exclusive with Encoding.
	Formats []S3Format `mapstructure:"formats"`
}

// sharedConfig defines configuration options shared between different AWS Lambda trigger types.
// Used for CloudWatch which remains single-format.
type sharedConfig struct {
	// Encoding defines the encoding to decode incoming Lambda invocation data.
	Encoding string `mapstructure:"encoding"`
}

type Config struct {
	// S3 defines configuration options for S3 Lambda trigger.
	S3 S3Config `mapstructure:"s3"`

	// CloudWatch defines configuration options for CloudWatch Lambda trigger.
	CloudWatch sharedConfig `mapstructure:"cloudwatch"`

	// FailureBucketARN is the ARN of receiver deployment Lambda's error destination.
	FailureBucketARN string `mapstructure:"failure_bucket_arn"`

	_ struct{} // Prevent unkeyed literal initialization
}

var _ component.Config = (*Config)(nil)

func createDefaultConfig() component.Config {
	return &Config{}
}

func (c *Config) Validate() error {
	if c.FailureBucketARN != "" {
		_, err := getBucketNameFromARN(c.FailureBucketARN)
		if err != nil {
			return fmt.Errorf("invalid failure_bucket_arn: %w", err)
		}
	}

	if err := c.S3.Validate(); err != nil {
		return fmt.Errorf("invalid s3 config: %w", err)
	}

	return nil
}

// Validate validates the S3 configuration.
func (c *S3Config) Validate() error {
	// Check mutual exclusivity
	if c.Encoding != "" && len(c.Formats) > 0 {
		return errors.New("'encoding' and 'formats' are mutually exclusive; use 'formats' for multi-format support")
	}

	// Validate each format entry
	for i, f := range c.Formats {
		if err := f.Validate(); err != nil {
			return fmt.Errorf("formats[%d]: %w", i, err)
		}
	}

	return nil
}

// SortedFormats returns a copy of Formats sorted by path pattern specificity.
// Empty patterns (catch-all) are placed last to ensure specific patterns match first.
func (c *S3Config) SortedFormats() []S3Format {
	if len(c.Formats) == 0 {
		return nil
	}

	// Create a copy to avoid modifying the original
	sorted := make([]S3Format, len(c.Formats))
	copy(sorted, c.Formats)

	sort.SliceStable(sorted, func(i, j int) bool {
		patternI := sorted[i].ResolvePathPattern()
		patternJ := sorted[j].ResolvePathPattern()

		// Empty patterns go last
		if patternI == "" && patternJ != "" {
			return false
		}
		if patternI != "" && patternJ == "" {
			return true
		}

		// For non-empty patterns, longer patterns are more specific, so they go first
		return len(patternI) > len(patternJ)
	})

	return sorted
}

// Validate validates an S3Format entry.
func (f *S3Format) Validate() error {
	if f.Name == "" {
		return errors.New("'name' is required")
	}

	// "*" is a valid catch-all pattern for any format name
	if f.PathPattern == CatchAllPattern {
		return nil
	}

	// If path_pattern is empty, check if there's a default for this format name
	if f.PathPattern == "" {
		if _, ok := defaultPathPatterns[f.Name]; !ok {
			return fmt.Errorf("'path_pattern' is required for format %q (no default available); use '%s' for catch-all", f.Name, CatchAllPattern)
		}
	}

	return nil
}

// ResolvePathPattern returns the path pattern to use for this format.
// It returns the configured pattern if set, otherwise the default for known formats.
// The special value "*" (CatchAllPattern) is resolved to empty string for matching.
func (f *S3Format) ResolvePathPattern() string {
	if f.PathPattern == CatchAllPattern {
		return "" // empty string matches everything with strings.Contains()
	}
	if f.PathPattern != "" {
		return f.PathPattern
	}
	return defaultPathPatterns[f.Name]
}

// getBucketNameFromARN extracts S3 bucket name from ARN
// Example
//
//	arn = "arn:aws:s3:::myBucket/folderA
//	result = myBucket
func getBucketNameFromARN(arn string) (string, error) {
	if !strings.HasPrefix(arn, s3ARNPrefix) {
		return "", fmt.Errorf("invalid S3 ARN format: %s", arn)
	}

	s3Path := strings.TrimPrefix(arn, s3ARNPrefix)
	bucket, _, _ := strings.Cut(s3Path, "/")

	if bucket == "" {
		return "", fmt.Errorf("invalid S3 ARN format, bucket name missing: %s", arn)
	}

	return bucket, nil
}
