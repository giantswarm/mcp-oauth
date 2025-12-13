package server

import (
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

// validateInterstitialConfig validates the InterstitialConfig for security and correctness.
// It checks branding values for injection attacks and logs warnings for custom handlers/templates.
func validateInterstitialConfig(config *Config, logger *slog.Logger) {
	// Skip validation if no interstitial configuration
	if config.Interstitial == nil {
		return
	}

	interstitial := config.Interstitial

	// SECURITY: Warn about custom handler - user is responsible for security
	if interstitial.CustomHandler != nil {
		logger.Warn("Custom interstitial handler configured",
			"responsibility", "You are responsible for setting security headers",
			"recommendation", "Use security.SetInterstitialSecurityHeaders() as a baseline",
			"csp_note", "If using inline scripts, update CSP headers with script hash")
	}

	// SECURITY: Warn about custom template - user is responsible for CSP
	if interstitial.CustomTemplate != "" {
		logger.Warn("Custom interstitial template configured",
			"template_length", len(interstitial.CustomTemplate),
			"csp_note", "If using inline scripts, ensure CSP headers include appropriate hashes")
	}

	// Validate branding configuration
	if interstitial.Branding != nil {
		validateInterstitialBranding(interstitial.Branding, config, logger)
	}
}

// validateInterstitialBranding validates the InterstitialBranding configuration
func validateInterstitialBranding(branding *InterstitialBranding, config *Config, logger *slog.Logger) {
	// SECURITY: Validate LogoURL is HTTPS or empty
	if branding.LogoURL != "" {
		u, err := url.Parse(branding.LogoURL)
		if err != nil {
			panic(fmt.Sprintf("Interstitial: invalid LogoURL '%s': %v", branding.LogoURL, err))
		}

		// Must be HTTPS (unless AllowInsecureHTTP is enabled for development)
		if u.Scheme != SchemeHTTPS {
			if config.AllowInsecureHTTP && u.Scheme == SchemeHTTP {
				logger.Warn("⚠️  Interstitial: HTTP LogoURL allowed for development",
					"logo_url", branding.LogoURL,
					"recommendation", "Use HTTPS LogoURL in production")
			} else {
				panic(fmt.Sprintf("Interstitial: LogoURL must use HTTPS scheme, got '%s' (or set AllowInsecureHTTP=true for development)", u.Scheme))
			}
		}

		// Warn if LogoAlt is not set (accessibility)
		if branding.LogoAlt == "" {
			logger.Warn("⚠️  Interstitial: LogoAlt not set for LogoURL",
				"logo_url", branding.LogoURL,
				"accessibility", "Consider setting LogoAlt for screen readers")
		}
	}

	// SECURITY: Validate CustomCSS doesn't contain injection vectors
	if branding.CustomCSS != "" {
		// Check for </style> tag injection
		if strings.Contains(strings.ToLower(branding.CustomCSS), "</style>") {
			panic("Interstitial: CustomCSS cannot contain '</style>' tag (injection risk)")
		}

		// Check for potentially dangerous CSS values
		if pattern, found := containsDangerousCSSPattern(branding.CustomCSS); found {
			panic(fmt.Sprintf("Interstitial: CustomCSS contains potentially dangerous pattern '%s'", pattern))
		}

		logger.Debug("Interstitial CustomCSS configured",
			"css_length", len(branding.CustomCSS))
	}

	// SECURITY: Validate color values are safe CSS (basic validation)
	if branding.PrimaryColor != "" {
		if err := validateCSSColorValue(branding.PrimaryColor); err != nil {
			panic(fmt.Sprintf("Interstitial: invalid PrimaryColor: %v", err))
		}
	}

	// SECURITY: Validate background gradient (basic validation)
	if branding.BackgroundGradient != "" {
		if err := validateCSSBackgroundValue(branding.BackgroundGradient); err != nil {
			panic(fmt.Sprintf("Interstitial: invalid BackgroundGradient: %v", err))
		}
	}

	logger.Debug("Interstitial branding configuration validated",
		"has_logo", branding.LogoURL != "",
		"has_title", branding.Title != "",
		"has_message", branding.Message != "",
		"has_button_text", branding.ButtonText != "",
		"has_primary_color", branding.PrimaryColor != "",
		"has_background", branding.BackgroundGradient != "",
		"has_custom_css", branding.CustomCSS != "")
}

// dangerousCSSPatterns contains patterns that indicate potential CSS injection attacks.
// These patterns are checked across all CSS value validations.
var dangerousCSSPatterns = []string{
	"expression(",  // IE CSS expression (JavaScript execution)
	"javascript:",  // JavaScript URL scheme
	"behavior:",    // IE CSS behavior
	"-moz-binding", // Firefox XBL binding (deprecated but still dangerous)
}

// containsDangerousCSSPattern checks if the value contains any dangerous CSS patterns.
// Returns the matched pattern and true if a dangerous pattern is found.
func containsDangerousCSSPattern(value string, additionalPatterns ...string) (string, bool) {
	lowerValue := strings.ToLower(value)

	// Check common dangerous patterns
	for _, pattern := range dangerousCSSPatterns {
		if strings.Contains(lowerValue, pattern) {
			return pattern, true
		}
	}

	// Check additional patterns specific to the context
	for _, pattern := range additionalPatterns {
		if strings.Contains(lowerValue, pattern) {
			return pattern, true
		}
	}

	return "", false
}

// validateCSSColorValue validates a CSS color value is safe
func validateCSSColorValue(color string) error {
	// Check for dangerous patterns (including url() which is not valid in color values)
	if pattern, found := containsDangerousCSSPattern(color, "url("); found {
		return fmt.Errorf("color value contains dangerous pattern '%s'", pattern)
	}

	// Basic format validation - must match common CSS color formats
	// Hex: #RGB, #RRGGBB, #RGBA, #RRGGBBAA
	// RGB/RGBA: rgb(), rgba()
	// HSL/HSLA: hsl(), hsla()
	// Named colors: allow alphanumeric
	colorPattern := regexp.MustCompile(`^(#[0-9a-fA-F]{3,8}|rgba?\([^)]+\)|hsla?\([^)]+\)|[a-zA-Z]+)$`)
	if !colorPattern.MatchString(strings.TrimSpace(color)) {
		return fmt.Errorf("invalid CSS color format: '%s'", color)
	}

	return nil
}

// validateCSSBackgroundValue validates a CSS background value is safe
func validateCSSBackgroundValue(bg string) error {
	// Check for dangerous patterns
	if pattern, found := containsDangerousCSSPattern(bg); found {
		return fmt.Errorf("background value contains dangerous pattern '%s'", pattern)
	}

	// Allow url() only for HTTPS URLs
	lowerBg := strings.ToLower(bg)
	if strings.Contains(lowerBg, "url(") {
		// Extract URL from url() and validate it's HTTPS
		urlPattern := regexp.MustCompile(`url\(['"]?([^'")]+)['"]?\)`)
		matches := urlPattern.FindAllStringSubmatch(bg, -1)
		for _, match := range matches {
			if len(match) > 1 {
				u, err := url.Parse(match[1])
				if err != nil || (u.Scheme != "" && u.Scheme != SchemeHTTPS) {
					return fmt.Errorf("url() in background must use HTTPS: '%s'", match[1])
				}
			}
		}
	}

	return nil
}
