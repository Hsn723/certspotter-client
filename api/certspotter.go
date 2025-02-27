package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/asaskevich/govalidator"
)

const (
	defaultParams = "?expand=dns_names&expand=issuer&expand=cert&expand=pubkey"
)

var (
	ErrorInvalidDomain = fmt.Errorf("an invalid domain name was provided")
)

// HTTPClient is an interface implementing for the http.Client Do function.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// CertspotterClient is a client for interacting with the certspotter API.
type CertspotterClient struct {
	Endpoint string
	Token    string
	Client   HTTPClient
}

// Issuance represents an issuance object for the certspotter API.
type Issuance struct {
	ID               uint64      `json:"id,string"`
	TBSSHA256        string      `json:"tbs_sha256"`
	Domains          []string    `json:"dns_names"`
	PubKeySHA256     string      `json:"pubkey_sha256"`
	Issuer           Issuer      `json:"issuer"`
	NotBefore        string      `json:"not_before"`
	NotAfter         string      `json:"not_after"`
	Cert             Certificate `json:"cert"` // deprecated
	CertDER          string      `json:"cert_der"`
	CertSHA256       string      `json:"cert_sha256"`
	ProblemReporting string      `json:"problem_reporting"`
	Revoked          bool        `json:"revoked"`
	Revocation       Revocation  `json:"revocation"`
	PubKey           PubKey      `json:"pubkey"`
}

// Issuer represents an issuer object for the certspotter API.
type Issuer struct {
	Name         string   `json:"name"`
	PubKeySHA256 string   `json:"pubkey_sha256"`
	FriendlyName string   `json:"friendly_name"`
	Website      string   `json:"website"`
	CAADomains   []string `json:"caa_domains"`
	Operator     Operator `json:"operator"`
}

// Certificate represents a certificate object for the certspotter API.
// This is now deprecated and Issuance.CertDER and Issuance.CertSHA256 should be used instead.
type Certificate struct {
	Type   string `json:"type"`
	SHA256 string `json:"sha256"`
	Data   string `json:"data"`
}

// Revocation represents a revocation object for the certspotter API.
type Revocation struct {
	Time      string `json:"time"`
	Reason    *int   `json:"reason"`
	CheckedAt string `json:"checked_at"`
}

// Operator represents an operator object for the certspotter API.
type Operator struct {
	Name    string `json:"name"`
	Website string `json:"website"`
}

// PubKey represents a pubkey object for the certspotter API.
type PubKey struct {
	Type      string `json:"type"`
	BitLength int    `json:"bit_length,omitempty"`
	Curve     string `json:"curve,omitempty"`
}

func (c *CertspotterClient) getQueryParams(domain string, matchWildcards, includeSubdomains bool, position uint64) string {
	q := fmt.Sprintf("%s&domain=%s", defaultParams, domain)
	if position > 0 {
		q = fmt.Sprintf("%s&after=%d", q, position)
	}
	if matchWildcards {
		q += "&match_wildcards=true"
	}
	if includeSubdomains {
		q += "&include_subdomains=true"
	}
	return q
}

func (c *CertspotterClient) get(queryParams string) ([]byte, error) {
	if c.Client == nil {
		c.Client = http.DefaultClient
	}
	req, err := http.NewRequest(http.MethodGet, c.Endpoint+queryParams, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	res, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusTooManyRequests {
		retryAfter := res.Header.Get("Retry-After")
		return nil, fmt.Errorf("hit Cert Spotter's API limit. Retry-After: %v", retryAfter)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("undocumented status code returned by the Cert Spotter API: %d", res.StatusCode)
	}
	return io.ReadAll(res.Body)
}

// GetIssuances queries the certspotter API for new issuances.
func (c *CertspotterClient) GetIssuances(domain string, matchWildcards, includeSubdomains bool, position uint64) ([]Issuance, error) {
	if !govalidator.IsDNSName(domain) {
		return nil, ErrorInvalidDomain
	}
	queryParams := c.getQueryParams(domain, matchWildcards, includeSubdomains, position)

	body, err := c.get(queryParams)
	if err != nil {
		return nil, err
	}
	var issuances []Issuance
	if err := json.Unmarshal(body, &issuances); err != nil {
		return nil, err
	}
	return issuances, nil
}
