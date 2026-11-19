package server

import "log/slog"

// blanketPrivateIPSwitch pairs a deprecated switch that lifts the private-IP
// check for every host with the host list it overrides and the setting that
// replaces it.
type blanketPrivateIPSwitch struct {
	field       string
	enabled     bool
	hostsField  string
	hosts       []string
	replacement string
}

// logPrivateIPHostDeprecations warns about each blanket private-IP switch in
// use. The switches keep their effect and override their host list.
func logPrivateIPHostDeprecations(config *Config, logger *slog.Logger) {
	for _, blanket := range []blanketPrivateIPSwitch{
		{"AllowPrivateIPClientMetadata", config.AllowPrivateIPClientMetadata, "AllowPrivateIPClientMetadataHosts", config.AllowPrivateIPClientMetadataHosts, "pre-register the clients in PreRegisteredClientMetadata"},
		{"AllowPrivateIPRedirectURIs", config.AllowPrivateIPRedirectURIs, "AllowPrivateIPRedirectURIHosts", config.AllowPrivateIPRedirectURIHosts, "list the hosts in AllowPrivateIPRedirectURIHosts"},
		{"AllowPrivateIPJWKS", config.AllowPrivateIPJWKS, "AllowPrivateIPJWKSHosts", config.AllowPrivateIPJWKSHosts, "list the hosts in AllowPrivateIPJWKSHosts"},
	} {
		if !blanket.enabled {
			continue
		}
		logger.Warn("DEPRECATED: " + blanket.field + " lifts the private-IP check for every host; " + blanket.replacement + " instead")
		if len(blanket.hosts) > 0 {
			logger.Warn(blanket.field+" overrides "+blanket.hostsField+": every host may resolve to a private address",
				"hosts", blanket.hosts)
		}
	}
}

// logTrustedIssuerPrivateIPDeprecations warns about trusted issuers that set
// the deprecated AllowPrivateIPJWKS.
func logTrustedIssuerPrivateIPDeprecations(issuers []TrustedIssuer, logger *slog.Logger) {
	for _, issuer := range issuers {
		if issuer.AllowPrivateIPJWKS {
			logger.Warn("DEPRECATED: TrustedIssuer.AllowPrivateIPJWKS lifts the private-IP check for every host; list the host in AllowPrivateIPJWKSHosts instead",
				"issuer", issuer.Issuer)
		}
	}
}
