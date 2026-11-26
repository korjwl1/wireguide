//go:build !darwin

package elevate

import "context"

func ValidateHelperSource(context.Context) error { return nil }
