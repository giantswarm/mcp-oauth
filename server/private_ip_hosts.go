package server

import (
	"log/slog"
	"slices"
)

// mergeHosts returns the hosts of both lists, each once, in first-seen order.
func mergeHosts(primary, deprecated []string) []string {
	if len(deprecated) == 0 {
		return primary
	}
	merged := slices.Clone(primary)
	for _, host := range deprecated {
		if !slices.Contains(merged, host) {
			merged = append(merged, host)
		}
	}
	return merged
}

// clientMetadataPrivateIPHosts returns ClientMetadataPrivateIPHosts together
// with its deprecated alias AllowPrivateIPClientMetadataHosts.
func (c *Config) clientMetadataPrivateIPHosts() []string {
	return mergeHosts(c.ClientMetadataPrivateIPHosts, c.AllowPrivateIPClientMetadataHosts)
}

// redirectURIPrivateIPHosts returns RedirectURIPrivateIPHosts together with its
// deprecated alias AllowPrivateIPRedirectURIHosts.
func (c *Config) redirectURIPrivateIPHosts() []string {
	return mergeHosts(c.RedirectURIPrivateIPHosts, c.AllowPrivateIPRedirectURIHosts)
}

// privateIPAllowance describes one operation's private-IP settings: the host
// list, the deprecated host list it absorbs and the deprecated blanket switch.
type privateIPAllowance struct {
	hostsField   string
	hosts        []string
	aliasField   string
	aliasHosts   []string
	blanketField string
	blanket      bool
}

// logPrivateIPHostDeprecations logs a warning for each deprecated private-IP
// setting in use. The deprecated host lists are read alongside their
// <Operation>PrivateIPHosts field, and the blanket switches keep their effect.
func logPrivateIPHostDeprecations(config *Config, logger *slog.Logger) {
	for _, allowance := range []privateIPAllowance{
		{
			hostsField: "ClientMetadataPrivateIPHosts", hosts: config.ClientMetadataPrivateIPHosts,
			aliasField: "AllowPrivateIPClientMetadataHosts", aliasHosts: config.AllowPrivateIPClientMetadataHosts,
			blanketField: "AllowPrivateIPClientMetadata", blanket: config.AllowPrivateIPClientMetadata,
		},
		{
			hostsField: "RedirectURIPrivateIPHosts", hosts: config.RedirectURIPrivateIPHosts,
			aliasField: "AllowPrivateIPRedirectURIHosts", aliasHosts: config.AllowPrivateIPRedirectURIHosts,
			blanketField: "AllowPrivateIPRedirectURIs", blanket: config.AllowPrivateIPRedirectURIs,
		},
		{
			hostsField: "JWKSPrivateIPHosts", hosts: config.JWKSPrivateIPHosts,
			blanketField: "AllowPrivateIPJWKS", blanket: config.AllowPrivateIPJWKS,
		},
	} {
		allowance.apply(logger)
	}
}

func (a privateIPAllowance) apply(logger *slog.Logger) {
	if len(a.aliasHosts) > 0 {
		logger.Warn("DEPRECATED: "+a.aliasField+" is renamed "+a.hostsField+"; both lists are honored",
			"hosts", a.aliasHosts)
	}
	if !a.blanket {
		return
	}
	logger.Warn("DEPRECATED: " + a.blanketField + " lifts the private-IP check for every host; list the hosts in " + a.hostsField + " instead")
	if hosts := mergeHosts(a.hosts, a.aliasHosts); len(hosts) > 0 {
		logger.Warn(a.blanketField+" overrides "+a.hostsField+": every host may resolve to a private address",
			"hosts", hosts)
	}
}

// logTrustedIssuerPrivateIPDeprecations warns about the deprecated private-IP
// settings of trusted issuers.
func logTrustedIssuerPrivateIPDeprecations(issuers []TrustedIssuer, logger *slog.Logger) {
	for _, issuer := range issuers {
		if len(issuer.AllowPrivateIPJWKSHosts) > 0 {
			logger.Warn("DEPRECATED: TrustedIssuer.AllowPrivateIPJWKSHosts is renamed JWKSPrivateIPHosts; both lists are honored",
				"issuer", issuer.Issuer, "hosts", issuer.AllowPrivateIPJWKSHosts)
		}
		if issuer.AllowPrivateIPJWKS {
			logger.Warn("DEPRECATED: TrustedIssuer.AllowPrivateIPJWKS lifts the private-IP check for every host; list the host in JWKSPrivateIPHosts instead",
				"issuer", issuer.Issuer)
		}
	}
}
