package server

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// KubernetesSATrust configures trust for a single Kubernetes cluster's
// projected ServiceAccount tokens.
type KubernetesSATrust struct {
	// Issuer is the cluster OIDC issuer URL (kube-apiserver --service-account-issuer).
	Issuer string
	// JwksURL is the JWKS endpoint. Independent of Issuer so an in-cluster
	// proxy can be used without changing the expected iss claim.
	JwksURL string
	// AllowedAudiences is the list of accepted aud values. Typically the
	// audience the token was projected with (e.g. the MCP server URL).
	// Empty accepts any audience (not recommended for production).
	AllowedAudiences []string
	// AllowedScopes is the scope ceiling for exchange tokens issued to
	// workloads from this cluster. Nil means no restriction.
	AllowedScopes []string
	// AllowedNamespaces restricts which namespaces may exchange tokens.
	// Empty means any namespace is allowed.
	AllowedNamespaces []string
	// AllowedServiceAccounts restricts which service accounts may exchange
	// tokens. Format: "namespace/name". Empty means any SA is allowed.
	AllowedServiceAccounts []string
}

// K8sSAValidator validates Kubernetes projected ServiceAccount tokens.
// It accepts subject_token_type values:
//   - urn:ietf:params:oauth:token-type:jwt
//   - urn:ietf:params:oauth:token-type:access_token
type K8sSAValidator struct {
	trusts        map[string]KubernetesSATrust
	oidcValidator *OIDCValidator
}

// NewK8sSAValidator constructs a K8sSAValidator. An SSRF-safe JWKS client is
// created automatically.
func NewK8sSAValidator(trusts []KubernetesSATrust) (*K8sSAValidator, error) {
	return newK8sSAValidatorWithClient(trusts, oidc.NewJWKSClient(nil, 0, nil))
}

// newK8sSAValidatorWithClient is the internal constructor used by tests to
// inject a custom JWKS client (e.g. one configured to allow private IPs).
func newK8sSAValidatorWithClient(trusts []KubernetesSATrust, client *oidc.JWKSClient) (*K8sSAValidator, error) {
	if len(trusts) == 0 {
		return nil, fmt.Errorf("at least one KubernetesSATrust is required")
	}

	issuers := make([]TrustedIssuer, 0, len(trusts))
	trustMap := make(map[string]KubernetesSATrust, len(trusts))
	for _, trust := range trusts {
		if trust.Issuer == "" {
			return nil, fmt.Errorf("KubernetesSATrust must have a non-empty Issuer")
		}
		if trust.JwksURL == "" {
			return nil, fmt.Errorf("KubernetesSATrust %q must have a non-empty JwksURL", trust.Issuer)
		}
		trustMap[trust.Issuer] = trust
		issuers = append(issuers, TrustedIssuer{
			Issuer:           trust.Issuer,
			JwksURL:          trust.JwksURL,
			AllowedAudiences: trust.AllowedAudiences,
			AllowedScopes:    trust.AllowedScopes,
		})
	}

	ov, err := newOIDCValidatorWithClient(issuers, client)
	if err != nil {
		return nil, err
	}
	return &K8sSAValidator{trusts: trustMap, oidcValidator: ov}, nil
}

// Validate verifies a Kubernetes projected SA token and returns the workload
// identity. It delegates signature and standard claim validation to the
// embedded OIDCValidator, then enforces any namespace/SA restrictions.
func (v *K8sSAValidator) Validate(ctx context.Context, subjectToken, subjectTokenType string) (SubjectIdentity, error) {
	switch subjectTokenType {
	case SubjectTokenTypeJWT, SubjectTokenTypeAccessToken:
	default:
		return SubjectIdentity{}, fmt.Errorf("unsupported subject_token_type: %q", subjectTokenType)
	}

	identity, err := v.oidcValidator.Validate(ctx, subjectToken, SubjectTokenTypeAccessToken)
	if err != nil {
		return SubjectIdentity{}, err
	}

	trust, ok := v.trusts[identity.Issuer]
	if !ok {
		return SubjectIdentity{}, fmt.Errorf("untrusted issuer: %q", identity.Issuer)
	}

	if err := v.checkSARestrictions(identity.Subject, trust); err != nil {
		return SubjectIdentity{}, err
	}

	return identity, nil
}

// checkSARestrictions enforces AllowedNamespaces and AllowedServiceAccounts.
// subject is expected in the form "system:serviceaccount:<namespace>:<name>".
func (v *K8sSAValidator) checkSARestrictions(subject string, trust KubernetesSATrust) error {
	if len(trust.AllowedNamespaces) == 0 && len(trust.AllowedServiceAccounts) == 0 {
		return nil
	}

	ns, name, ok := parseSASubject(subject)
	if !ok {
		return fmt.Errorf("subject %q is not a service account principal", subject)
	}

	if len(trust.AllowedNamespaces) > 0 {
		if !slices.Contains(trust.AllowedNamespaces, ns) {
			return fmt.Errorf("namespace %q is not in the allowed list", ns)
		}
	}

	if len(trust.AllowedServiceAccounts) > 0 {
		qualified := ns + "/" + name
		if !slices.Contains(trust.AllowedServiceAccounts, qualified) {
			return fmt.Errorf("service account %q is not in the allowed list", qualified)
		}
	}

	return nil
}

// parseSASubject parses "system:serviceaccount:<namespace>:<name>".
func parseSASubject(subject string) (namespace, name string, ok bool) {
	const prefix = "system:serviceaccount:"
	rest, found := strings.CutPrefix(subject, prefix)
	if !found {
		return "", "", false
	}
	namespace, name, ok = strings.Cut(rest, ":")
	return
}
