package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// signES256 returns a compact JWS signed with key, with key's public half in
// the header's jwk member, as in a DPoP proof.
func signES256(t *testing.T, key *ecdsa.PrivateKey, payload map[string]interface{}) string {
	t.Helper()
	ecdhKey, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	point := ecdhKey.Bytes()
	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(point[1:33]),
			"y":   base64.RawURLEncoding.EncodeToString(point[33:]),
		},
	}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestExtractJWTs(t *testing.T) {
	const token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.c2ln"
	tests := []struct {
		name  string
		input string
	}{
		{"bare token", token},
		{"surrounding whitespace", "\n  " + token + "  \n"},
		{"DPoP header line", "DPoP: " + token},
		{"Authorization Bearer header line", "Authorization: Bearer " + token},
		{"Authorization DPoP header line", "authorization: DPoP " + token},
		{"quoted", `"` + token + `"`},
		{"wrapped inside a part", "dpop:          eyJhbGciOiJub2\n               5lIn0.eyJzdWIiOiJ4In0.c2\n               ln\nx-request-id:  abc123"},
		{"wrapped after a dot", "dpop:  eyJhbGciOiJub25lIn0.\n       eyJzdWIiOiJ4In0.c2ln"},
		{"among other headers", "content-type:  text/xml\nuser-agent:    force/dev (linux-amd64)\ndpop:          " + token + "\nx-content-type-options:  nosniff"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractJWTs(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0] != token {
				t.Errorf("got %q", got)
			}
		})
	}
}

func TestExtractJWTs_returns_every_jwt_in_the_input(t *testing.T) {
	const first = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln"
	const second = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIyIn0.c2ln"
	got, err := extractJWTs("authorization:  Bearer " + first + "\ndpop:           " + second + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != first || got[1] != second {
		t.Errorf("got %q", got)
	}
}

func TestExtractJWTs_rejects_input_without_a_jwt(t *testing.T) {
	for _, input := range []string{"", "   ", "DPoP: not-a-token", "a.b.c", "Authorization: DPoP 00Dxx0000000000!AQEAabc"} {
		if _, err := extractJWTs(input); err == nil {
			t.Errorf("no error for %q", input)
		}
	}
}

func TestReadInput_reads_standard_input_to_eof(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		w.WriteString("line one\nline two\n")
		w.Close()
	}()
	got, err := readInput(nil, r)
	if err != nil {
		t.Fatal(err)
	}
	if got != "line one\nline two\n" {
		t.Errorf("got %q", got)
	}
}

func TestRun_decodes_each_jwt_in_pasted_headers(t *testing.T) {
	a := signES256(t, newKey(t), map[string]interface{}{"htm": "GET"})
	b := signES256(t, newKey(t), map[string]interface{}{"htm": "POST"})
	var out strings.Builder
	if err := run("dpop: "+a+"\nx-other: 1\ndpop: "+b, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"== JWT 1 of 2 ==", "== JWT 2 of 2 ==", `"htm": "GET"`, `"htm": "POST"`} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRun_prints_header_payload_thumbprint_and_valid_signature_for_a_dpop_proof(t *testing.T) {
	proof := signES256(t, newKey(t), map[string]interface{}{
		"jti":   "abc",
		"htm":   "POST",
		"htu":   "https://example.my.salesforce.com/services/oauth2/token",
		"iat":   1795622400,
		"nonce": "the-nonce",
	})
	var out strings.Builder
	if err := run("DPoP: "+proof, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		`"typ": "dpop+jwt"`,
		`"htu": "https://example.my.salesforce.com/services/oauth2/token"`,
		`"nonce": "the-nonce"`,
		"iat: 2026-",
		"Signature: 64 bytes",
		"JWK thumbprint: ",
		"Signature check with the header's jwk: valid",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRun_reports_a_signature_that_does_not_match_the_header_jwk(t *testing.T) {
	proof := signES256(t, newKey(t), map[string]interface{}{"htm": "GET"})
	other := signES256(t, newKey(t), map[string]interface{}{"htm": "GET"})
	// Keep the first proof's header and payload with the other key's signature.
	parts := strings.Split(proof, ".")
	tampered := parts[0] + "." + parts[1] + "." + strings.Split(other, ".")[2]

	var out strings.Builder
	if err := run(tampered, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Signature check with the header's jwk: FAILED") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestRun_decodes_a_jwt_without_a_jwk(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"005000000000001","exp":4102444800}`))
	var out strings.Builder
	if err := run(header+"."+payload+".c2ln", &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, `"sub": "005000000000001"`) || !strings.Contains(got, "exp: 2100-01-01") {
		t.Errorf("output:\n%s", got)
	}
	if strings.Contains(got, "thumbprint") {
		t.Errorf("printed a thumbprint without a jwk:\n%s", got)
	}
}

func TestJWKThumbprint_matches_the_rfc_7638_example(t *testing.T) {
	// RFC 7638 section 3.1.
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	}
	got, err := jwkThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestDecodeSegment_accepts_padded_base64url(t *testing.T) {
	got, err := decodeSegment("eyJhIjoxfQ==")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":1}` {
		t.Errorf("got %q", got)
	}
}
