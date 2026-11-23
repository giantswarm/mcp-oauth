package server

import (
	"fmt"
	"net/url"
	"strings"
)

func parseResourceURI(resource string) (*url.URL, error) {
	if len(resource) > MaxResourceLength {
		return nil, fmt.Errorf("resource exceeds maximum length of %d characters", MaxResourceLength)
	}
	resourceURL, err := url.Parse(resource)
	if err != nil {
		return nil, fmt.Errorf("resource must be a valid URI: %w", err)
	}
	if !resourceURL.IsAbs() {
		return nil, fmt.Errorf("resource must be an absolute URI")
	}
	if strings.Contains(resource, "#") {
		return nil, fmt.Errorf("resource must not contain fragment identifier")
	}
	return resourceURL, nil
}
