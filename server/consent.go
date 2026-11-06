package server

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
)

// TrustedClient is a client the operator approved in advance. An
// authorization request from ClientID to one of RedirectURIs goes to the
// upstream identity provider without the consent page.
//
// ClientID is a Client ID Metadata Document URL or the ID of a pre-registered
// client. RedirectURIs are exact https URIs on a non-loopback host: trust is
// never extended to a redirect URI the operator did not name, so a change to a
// client's metadata document cannot widen it.
type TrustedClient struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
}

// AuthorizationRequest is an /authorize request that passed every check and
// has not started the upstream flow yet. [Server.PrepareAuthorization] builds
// it and [Server.BeginAuthorization] starts the flow from it.
type AuthorizationRequest struct {
	ClientID            string                             `json:"client_id"`
	RedirectURI         string                             `json:"redirect_uri"`
	Scope               string                             `json:"scope,omitempty"`
	Resource            string                             `json:"resource,omitempty"`
	State               string                             `json:"state,omitempty"`
	CodeChallenge       string                             `json:"code_challenge,omitempty"`
	CodeChallengeMethod string                             `json:"code_challenge_method,omitempty"`
	Options             *providers.AuthorizationURLOptions `json:"options,omitempty"`

	// ClientName is the name the client gives itself. It is chosen by the
	// client, so it is shown as a claim, never as the client's identity.
	ClientName string `json:"-"`

	// LoopbackOnly reports that every redirect URI of the client is a
	// loopback address, so any program on the person's computer can claim
	// to be this client.
	LoopbackOnly bool `json:"-"`

	// checked is set only by PrepareAuthorization, so a request built or
	// decoded elsewhere is checked again before its flow starts.
	checked bool
}

// ErrClientNotVerified marks an authorization request whose client could not
// be found or whose metadata document could not be fetched and validated.
var ErrClientNotVerified = errors.New("client could not be verified")

// ConsentKey identifies the person's approval of this request. Two requests
// share a key when they come from the same client, go to the same registered
// redirect URI and ask for the same scopes and resource. The port of a
// loopback redirect URI is left out because native apps bind a new port on
// every run.
func (r *AuthorizationRequest) ConsentKey() string {
	scopes := helpers.SplitScopes(r.Scope)
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)

	h := sha256.New()
	for _, part := range []string{"mcp-oauth consent v1", r.ClientID, redirectURIWithoutLoopbackPort(r.RedirectURI), strings.Join(scopes, " "), r.Resource} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}

// RequiresConsent reports whether the person has to approve the request
// before it goes to the upstream identity provider: every client except a
// TrustedClient whose entry names the request's redirect URI.
func (s *Server) RequiresConsent(clientID, redirectURI string) bool {
	for _, trusted := range s.Config.TrustedClients {
		if trusted.ClientID == clientID {
			return !slices.Contains(trusted.RedirectURIs, redirectURI)
		}
	}
	return true
}

// redirectURIWithoutLoopbackPort returns uri with the port removed when the
// host is a loopback address, and uri unchanged otherwise.
func redirectURIWithoutLoopbackPort(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil || !isLoopbackAddress(parsed.Hostname()) || parsed.Port() == "" {
		return uri
	}
	parsed.Host = parsed.Hostname()
	if strings.Contains(parsed.Host, ":") {
		parsed.Host = "[" + parsed.Host + "]"
	}
	return parsed.String()
}

// validateTrustedClients refuses a trust list that could extend trust beyond
// what the operator named: empty or duplicate client IDs, a Client ID Metadata
// Document URL without a path, and redirect URIs that are not exact https URIs
// on a non-loopback host.
func validateTrustedClients(clients []TrustedClient) error {
	seen := make(map[string]bool, len(clients))
	for i, client := range clients {
		if seen[client.ClientID] {
			return fmt.Errorf("TrustedClients[%d]: client_id %q is listed twice", i, client.ClientID)
		}
		seen[client.ClientID] = true
		if err := validateTrustedClient(client); err != nil {
			return fmt.Errorf("TrustedClients[%d]: %w", i, err)
		}
	}
	return nil
}

func validateTrustedClient(client TrustedClient) error {
	if client.ClientID == "" {
		return fmt.Errorf("client_id is empty")
	}
	if strings.HasPrefix(client.ClientID, SchemeHTTPS+"://") {
		u, err := url.Parse(client.ClientID)
		if err != nil || !isURLClientID(client.ClientID) || u.Path == "" || u.Path == "/" || strings.Contains(u.Host, "*") {
			return fmt.Errorf("client_id %q is not a client ID metadata document URL with a path", client.ClientID)
		}
	}
	if len(client.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris is empty")
	}
	for _, uri := range client.RedirectURIs {
		if err := validateTrustedRedirectURI(uri); err != nil {
			return fmt.Errorf("redirect URI %q: %w", uri, err)
		}
	}
	return nil
}

func validateTrustedRedirectURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}
	if u.Scheme != SchemeHTTPS {
		return fmt.Errorf("must use https")
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "*") {
		return fmt.Errorf("must name a single host")
	}
	if ip := net.ParseIP(host); isLoopbackAddress(host) || ip != nil && ip.IsUnspecified() {
		return fmt.Errorf("must not be a loopback address: loopback clients always see the consent page")
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("must not carry userinfo or a fragment")
	}
	return nil
}
