package cimd

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Document represents an OAuth 2.0 Client ID Metadata Document (CIMD)
// per draft-ietf-oauth-client-id-metadata-document.
type Document struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
}

// ValidateDocument validates that the document meets draft-ietf-oauth-client-id-metadata-document requirements.
func ValidateDocument(doc *Document, expectedClientID string) error {
	if doc == nil {
		return fmt.Errorf("document is nil")
	}
	if doc.ClientID == "" {
		return fmt.Errorf("document is missing client_id")
	}
	if doc.ClientID != expectedClientID {
		return fmt.Errorf("document client_id %q does not match requested client_id %q", doc.ClientID, expectedClientID)
	}
	if len(doc.RedirectURIs) == 0 {
		return fmt.Errorf("document must contain at least one redirect_uri")
	}
	for _, rawURI := range doc.RedirectURIs {
		u, err := url.Parse(rawURI)
		if err != nil || !u.IsAbs() {
			return fmt.Errorf("invalid redirect_uri in document: %q", rawURI)
		}
		if u.Fragment != "" {
			return fmt.Errorf("redirect_uri must not contain fragment: %q", rawURI)
		}
	}
	return nil
}

// ValidateRedirectURI checks if requestedURI is authorized by the client metadata document.
// In accordance with RFC 8252 Section 7.3 (OAuth 2.0 for Native Apps):
// If the requested URI is a local loopback URL (localhost, 127.0.0.1, ::1), the port can be dynamic
// as native apps bind to ephemeral ports. The scheme, host category (loopback), and path must match
// an allowed loopback URI in the document.
// For non-loopback URIs, exact string match is enforced.
func ValidateRedirectURI(doc *Document, requestedURI string) bool {
	if doc == nil || requestedURI == "" {
		return false
	}
	reqU, err := url.Parse(requestedURI)
	if err != nil || !reqU.IsAbs() || reqU.Fragment != "" {
		return false
	}

	reqHost := reqU.Hostname()
	reqIsLoopback := isLoopbackHost(reqHost)

	for _, allowed := range doc.RedirectURIs {
		// Exact string match check
		if allowed == requestedURI {
			return true
		}

		if reqIsLoopback {
			allowU, err := url.Parse(allowed)
			if err != nil || !allowU.IsAbs() {
				continue
			}
			if isLoopbackHost(allowU.Hostname()) {
				// Scheme and path must match for loopback (treating empty path and / identically)
				if strings.EqualFold(allowU.Scheme, reqU.Scheme) && normalizePath(allowU.Path) == normalizePath(reqU.Path) {
					return true
				}
			}
		}
	}

	return false
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	return strings.TrimRight(p, "/")
}
