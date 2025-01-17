package api

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type MockClient struct {
	Content string
}

func (c MockClient) Do(req *http.Request) (*http.Response, error) {
	res := &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(strings.NewReader(c.Content)),
	}
	return res, nil
}

func testGetQueryParams(c CertspotterClient, d string, wild, sub bool, pos uint64, expected string, t *testing.T) {
	t.Helper()
	actual := c.getQueryParams(d, wild, sub, pos)
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}

func TestGetQueryParams(t *testing.T) {
	cases := []struct {
		title     string
		domain    string
		wildcard  bool
		subdomain bool
		position  uint64
		expected  string
	}{
		{
			title:     "testGetQueryParams_DomainOnly",
			domain:    "example.com",
			wildcard:  false,
			subdomain: false,
			position:  0,
			expected:  "?expand=dns_names&expand=issuer&expand=cert&expand=pubkey&domain=example.com",
		},
		{
			title:     "testGetQueryParams_WildcardOnly",
			domain:    "example.com",
			wildcard:  true,
			subdomain: false,
			position:  0,
			expected:  "?expand=dns_names&expand=issuer&expand=cert&expand=pubkey&domain=example.com&match_wildcards=true",
		},
		{
			title:     "testGetQueryParams_SubdomainOnly",
			domain:    "example.com",
			wildcard:  false,
			subdomain: true,
			position:  0,
			expected:  "?expand=dns_names&expand=issuer&expand=cert&expand=pubkey&domain=example.com&include_subdomains=true",
		},
		{
			title:     "testGetQueryParams_WithPosition",
			domain:    "example.com",
			wildcard:  false,
			subdomain: false,
			position:  1234567,
			expected:  "?expand=dns_names&expand=issuer&expand=cert&expand=pubkey&domain=example.com&after=1234567",
		},
		{
			title:     "testGetQueryParams_All",
			domain:    "example.com",
			wildcard:  true,
			subdomain: true,
			position:  1234567,
			expected:  "?expand=dns_names&expand=issuer&expand=cert&expand=pubkey&domain=example.com&after=1234567&match_wildcards=true&include_subdomains=true",
		},
	}

	cc := CertspotterClient{
		Endpoint: "",
		Token:    "",
		Client:   http.DefaultClient,
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			testGetQueryParams(cc, tc.domain, tc.wildcard, tc.subdomain, tc.position, tc.expected, t)
		})
	}
}

func TestGetIssuancesEmpty(t *testing.T) {
	mockClient := MockClient{
		Content: "[]",
	}
	cc := CertspotterClient{
		Client: mockClient,
	}
	expected := []Issuance{}
	actual, err := cc.GetIssuances("example.com", true, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("expected %v, got %v", expected, actual)
	}
}

func TestGetIssuanceInvalidDomain(t *testing.T) {
	mockClient := MockClient{
		Content: "[]",
	}
	cc := CertspotterClient{
		Client: mockClient,
	}
	actual, err := cc.GetIssuances("*.example.com", true, true, 0)
	if !errors.Is(err, ErrorInvalidDomain) {
		t.Errorf("expected %v, got %v", ErrorInvalidDomain, err)
	}
	if actual != nil {
		t.Errorf("expected nil, got %v", actual)
	}
}

func TestGetIssuancesWithResult(t *testing.T) {
	mockClient := MockClient{
		Content: `[
			{
				"id":"4326219514",
				"tbs_sha256":"db7c55f74732269c45fda91264003b2a25adc7ff2df687252f60772850449926",
				"cert_sha256":"20cbc0d1e87ed1d71d3b84533667ef60f22fffee634108711376dec87a38d4e2",
				"dns_names":["certs.sandbox.sslmate.com","certs.sslmate.com","sandbox.sslmate.com","sslmate.com","www.sslmate.com"],
				"pubkey_sha256":"1b1cebcd061ba39746a477db7b90d6871d648bd293ef50e053a6c54c5c3ac112",
				"pubkey":{"type":"rsa","bit_length":2048},
				"issuer":{
					"friendly_name":"Sectigo",
					"website":"https://sectigo.com/",
					"caa_domains":["sectigo.com","comodo.com","comodoca.com","usertrust.com","trust-provider.com"],
					"operator":{"name":"Sectigo","website":"https://sectigo.com/"},
					"pubkey_sha256":"e1ae9c3de848ece1ba72e0d991ae4d0d9ec547c6bad1dddab9d6beb0a7e0e0d8",
					"pubkey_der":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1nMz1tc8INAA0hdFuNY+B6I/x0HuMjDJsGz99J/LEpgPLT+NTQEMgg8Xf2Iu6bhIefsWg06t1zIlk7cHv7lQP6lMw0Aq6Tn/2YHKHxYyQdqAJrkjeocgHuP/IJo8lURvh3UGkEC0MpMWCRAIIz7S3YcPb11RFGoKacVPAXJpz9OTTG0EoKMbgn6xmrntxZ7FN3ifmgg0+1YuWMQJDgZkW7w33PGfKGioVrCSo1yfu4iYCBskHaswha6vsC6eep3BwEIc4gLw6uBK0u+QDrTBQBbwb4VCSmT3pDCg/r8uoydajotYuK3DGReEY+1vVv2Dy2A0xHS+5p3b4eTlygxfFQIDAQAB",
					"name":"C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA",
					"name_der":"MIGPMQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxNzA1BgNVBAMTLlNlY3RpZ28gUlNBIERvbWFpbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIgQ0E="
				},
				"not_before":"2022-10-22T00:00:00Z",
				"not_after":"2023-11-21T23:59:59Z",
				"revoked":false,
				"revocation":{"time":null,"reason":null,"checked_at":"2022-12-19T18:47:39Z"},
				"problem_reporting":"To revoke one or more certificates issued by Sectigo for which you (i) are the Subscriber or (ii) control the domain or (iii) have in your possession the private key, you may use our automated Revocation Portal here:\u000A  ?? https://secure.sectigo.com/products/RevocationPortal\u000A\u000ATo programatically revoke one or more certificates issued by Sectigo for which you have in your possession the private key, you may use the ACME revokeCert method at this endpoint:\u000A  ?? ACME Directory: https://acme.sectigo.com/v2/keyCompromise\u000A  ?? revokeCert API: https://acme.sectigo.com/v2/keyCompromise/revokeCert\u000A\u000ATo report any other abuse, fraudulent, or malicious use of Certificates issued by Sectigo, please send email to:\u000A  ?? For Code Signing Certificates: signedmalwarealert[at]sectigo[dot]com\u000A  ?? For Other Certificates (SSL/TLS, S/MIME, etc): sslabuse[at]sectigo[dot]com",
				"cert_der":"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"
			}
	]
	`,
	}
	cc := CertspotterClient{
		Client: mockClient,
	}
	expected := []Issuance{
		{
			ID:        4326219514,
			TBSSHA256: "db7c55f74732269c45fda91264003b2a25adc7ff2df687252f60772850449926",
			Domains: []string{
				"certs.sandbox.sslmate.com",
				"certs.sslmate.com",
				"sandbox.sslmate.com",
				"sslmate.com",
				"www.sslmate.com",
			},
			PubKeySHA256: "1b1cebcd061ba39746a477db7b90d6871d648bd293ef50e053a6c54c5c3ac112",
			PubKey: PubKey{
				Type: "rsa",
				BitLength: 2048,
			},
			Issuer: Issuer{
				Name:         "C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA",
				PubKeySHA256: "e1ae9c3de848ece1ba72e0d991ae4d0d9ec547c6bad1dddab9d6beb0a7e0e0d8",
				FriendlyName: "Sectigo",
				Website:      "https://sectigo.com/",
				CAADomains: []string{
					"sectigo.com",
					"comodo.com",
					"comodoca.com",
					"usertrust.com",
					"trust-provider.com",
				},
				Operator: Operator{
					Name:    "Sectigo",
					Website: "https://sectigo.com/",
				},
			},
			NotBefore:        "2022-10-22T00:00:00Z",
			NotAfter:         "2023-11-21T23:59:59Z",
			ProblemReporting: "To revoke one or more certificates issued by Sectigo for which you (i) are the Subscriber or (ii) control the domain or (iii) have in your possession the private key, you may use our automated Revocation Portal here:\u000A  ?? https://secure.sectigo.com/products/RevocationPortal\u000A\u000ATo programatically revoke one or more certificates issued by Sectigo for which you have in your possession the private key, you may use the ACME revokeCert method at this endpoint:\u000A  ?? ACME Directory: https://acme.sectigo.com/v2/keyCompromise\u000A  ?? revokeCert API: https://acme.sectigo.com/v2/keyCompromise/revokeCert\u000A\u000ATo report any other abuse, fraudulent, or malicious use of Certificates issued by Sectigo, please send email to:\u000A  ?? For Code Signing Certificates: signedmalwarealert[at]sectigo[dot]com\u000A  ?? For Other Certificates (SSL/TLS, S/MIME, etc): sslabuse[at]sectigo[dot]com",
			Revoked:          false,
			Revocation: Revocation{
				CheckedAt: "2022-12-19T18:47:39Z",
				Time:      "",
				Reason:    nil,
			},
			CertSHA256: "20cbc0d1e87ed1d71d3b84533667ef60f22fffee634108711376dec87a38d4e2",
			CertDER:    "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",
		},
	}
	actual, err := cc.GetIssuances("sslmate.com", true, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("expected %v, got %v", expected, actual)
	}
}
