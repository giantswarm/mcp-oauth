package oauthconfig

import (
	"fmt"
	"os"
	"slices"
)

// SettingsFromEnv reads every OAUTH_* variable into the [Settings] that
// [Setup] takes, so a server's whole OAuth setup is:
//
//	settings, err := oauthconfig.SettingsFromEnv()
//	...
//	runtime, cleanup, err := oauthconfig.Setup(settings)
//
// It combines [FromEnv], the provider selected by OAUTH_PROVIDER, the storage
// and encryption variables of [StorageFromEnv] and [NewEncryptorFromEnv], and
// [TrustedIssuersFromEnv]. OAUTH_DEX_CA_FILE supplies one shared CA pool for
// the provider and its forwarded ID tokens. Each advertised
// authorization server must be the server's own issuer or a trusted issuer,
// since an MCP client only presents tokens from the servers it was pointed at.
//
// Logger and Instrumentation are left for the caller to set.
func SettingsFromEnv() (Settings, error) {
	return SettingsFromEnvWithPrefix("OAUTH_")
}

// SettingsFromEnvWithPrefix is [SettingsFromEnv] with a caller-supplied
// prefix. See [FromEnvWithPrefix] for the convention.
func SettingsFromEnvWithPrefix(prefix string) (Settings, error) {
	var settings Settings
	var err error
	if settings.Server, err = FromEnvWithPrefix(prefix); err != nil {
		return Settings{}, err
	}
	if err := providerSettingsFromEnv(prefix, &settings); err != nil {
		return Settings{}, err
	}
	if settings.Valkey, err = storageConfigFromEnv(prefix); err != nil {
		return Settings{}, err
	}
	if settings.Encryptor, err = NewEncryptorFromEnvWithPrefix(prefix); err != nil {
		return Settings{}, err
	}
	if settings.TrustedIssuers, err = TrustedIssuersFromEnvWithPrefix(prefix); err != nil {
		return Settings{}, err
	}
	if err := checkAdvertisedAuthorizationServers(prefix, settings); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func providerSettingsFromEnv(prefix string, settings *Settings) error {
	var err error
	switch name := os.Getenv(prefix + "PROVIDER"); name {
	case "dex":
		settings.Dex, err = dexConfigFromEnv(prefix)
		if err == nil {
			settings.Server.JWKSRootCAs = settings.Dex.RootCAs
		}
	case "google":
		settings.Google, err = googleConfigFromEnv(prefix)
	case "github":
		settings.GitHub, err = githubConfigFromEnv(prefix)
	case "":
		err = fmt.Errorf("%sPROVIDER is required (one of: dex, google, github)", prefix)
	default:
		err = fmt.Errorf("%sPROVIDER: unknown provider %q (want dex, google, or github)", prefix, name)
	}
	return err
}

func checkAdvertisedAuthorizationServers(prefix string, settings Settings) error {
	known := []string{settings.Server.Issuer}
	for _, issuer := range settings.TrustedIssuers {
		known = append(known, issuer.Issuer)
	}
	for _, resource := range settings.Server.ResourceMetadataByPath {
		for _, advertised := range resource.AuthorizationServers {
			if !slices.Contains(known, advertised) {
				return fmt.Errorf("%sAUTHORIZATION_SERVERS: %q is neither %sISSUER nor in %sTRUSTED_ISSUERS", prefix, advertised, prefix, prefix)
			}
		}
	}
	return nil
}
