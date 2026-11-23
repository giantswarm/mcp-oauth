package server

import (
	"crypto/subtle"
	"fmt"
	"net/url"
	"strings"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
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
	if !validResourceURIComponents(resource, resourceURL) {
		return nil, fmt.Errorf("resource contains invalid URI characters or percent encoding")
	}
	return resourceURL, nil
}

func validResourceURIComponents(resource string, parsed *url.URL) bool {
	path, _, _ := strings.Cut(resource[len(parsed.Scheme)+1:], "?")
	if strings.HasPrefix(path, "//") {
		authority, remaining, _ := strings.Cut(path[2:], "/")
		if strings.Count(authority, "@") > 1 || !validURICharacters(authority, ":@[]") {
			return false
		}
		path = remaining
	}
	return validURICharacters(path, ":@/") && validURICharacters(parsed.RawQuery, ":@/?")
}

func validURICharacters(value, delimiters string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '%' {
			if index+2 >= len(value) || !isURIHex(value[index+1]) || !isURIHex(value[index+2]) {
				return false
			}
			index += 2
			continue
		}
		if strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;="+delimiters, rune(character)) {
			continue
		}
		return false
	}
	return true
}

func isURIHex(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F'
}

func normalizeResourceURI(resource string) (string, error) {
	if _, err := parseResourceURI(resource); err != nil {
		return "", err
	}
	return helpers.NormalizeURL(resource), nil
}

func resourcesMatch(left, right string) bool {
	normalizedLeft, err := normalizeResourceURI(left)
	if err != nil {
		return false
	}
	normalizedRight, err := normalizeResourceURI(right)
	return err == nil && subtle.ConstantTimeCompare([]byte(normalizedLeft), []byte(normalizedRight)) == 1
}
