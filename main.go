// Command jwt decodes a JSON Web Token and prints its header and payload.
//
// The token can be given as an argument or pasted on standard input. Header
// names and authorization schemes in front of the token, as in
// "DPoP: eyJ..." or "Authorization: Bearer eyJ...", are ignored. When the
// header carries a public key in its jwk member, as a DPoP proof does, the
// signature is checked against that key and the key's JWK thumbprint
// (RFC 7638) is printed.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"strings"
	"time"
)

func main() {
	input, err := readInput(os.Args[1:], os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jwt:", err)
		os.Exit(1)
	}
	if err := run(input, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "jwt:", err)
		os.Exit(1)
	}
}

// readInput returns the arguments joined with spaces, or, without arguments,
// standard input read to EOF. Reading to EOF lets a paste span several
// lines, such as a block of request headers copied from a proxy.
func readInput(args []string, stdin *os.File) (string, error) {
	if len(args) > 0 {
		return strings.Join(args, " "), nil
	}
	if info, err := stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "Paste a JWT or request headers, then press Ctrl+D:")
	}
	data, err := io.ReadAll(stdin)
	return string(data), err
}

func run(input string, w io.Writer) error {
	tokens, err := extractJWTs(input)
	if err != nil {
		return err
	}
	for i, token := range tokens {
		if len(tokens) > 1 {
			if i > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "== JWT %d of %d ==\n", i+1, len(tokens))
		}
		if err := printJWT(token, w); err != nil {
			if len(tokens) == 1 {
				return err
			}
			fmt.Fprintf(w, "error: %v\n", err)
		}
	}
	return nil
}

func printJWT(token string, w io.Writer) error {
	decoded, err := decode(token)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "Header:")
	fmt.Fprintln(w, indentJSON(decoded.rawHeader))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Payload:")
	fmt.Fprintln(w, indentJSON(decoded.rawPayload))

	if times := claimTimes(decoded.payload); len(times) > 0 {
		fmt.Fprintln(w)
		for _, t := range times {
			fmt.Fprintln(w, t)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Signature: %d bytes\n", len(decoded.signature))
	jwk, ok := decoded.header["jwk"].(map[string]interface{})
	if !ok {
		return nil
	}
	thumbprint, err := jwkThumbprint(jwk)
	if err != nil {
		fmt.Fprintf(w, "JWK thumbprint: %v\n", err)
	} else {
		fmt.Fprintf(w, "JWK thumbprint: %s\n", thumbprint)
	}
	alg, _ := decoded.header["alg"].(string)
	if err := verify(alg, jwk, decoded.signingInput, decoded.signature); err != nil {
		fmt.Fprintf(w, "Signature check with the header's jwk: FAILED: %v\n", err)
	} else {
		fmt.Fprintln(w, "Signature check with the header's jwk: valid")
	}
	return nil
}

// extractJWTs returns the JWTs in input. Text around them, such as header
// names ("DPoP:"), authorization schemes ("Bearer"), and other headers, is
// skipped. A JWT starts with "eyJ", the base64url encoding of the '{"' that
// begins its JSON header. Tools such as mitmproxy wrap a long header value
// onto continuation lines, so the whitespace-separated fields that follow a
// JWT's start and contain only base64url characters and dots are joined to
// it, up to the third part. A field that starts another JWT, or that holds
// other characters, such as the next header's "name:", ends the JWT.
func extractJWTs(input string) ([]string, error) {
	if strings.TrimSpace(input) == "" {
		return nil, errors.New("no input")
	}
	fields := strings.Fields(input)
	for i := range fields {
		fields[i] = strings.Trim(fields[i], `"',;`)
	}
	var tokens []string
	for i := 0; i < len(fields); i++ {
		if !strings.HasPrefix(fields[i], "eyJ") || !isTokenText(fields[i]) {
			continue
		}
		token := fields[i]
		for i+1 < len(fields) {
			next := fields[i+1]
			if !isTokenText(next) || strings.Count(token+next, ".") > 2 {
				break
			}
			// A field starting with "eyJ" continues this JWT only when
			// the line broke right after a dot.
			if strings.HasPrefix(next, "eyJ") && !strings.HasSuffix(token, ".") {
				break
			}
			token += next
			i++
		}
		if strings.Count(token, ".") == 2 {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return nil, errors.New("no JWT found: expected three base64url parts separated by dots, starting with eyJ")
	}
	return tokens, nil
}

// isTokenText reports whether s holds only base64url characters, padding,
// and dots.
func isTokenText(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == '=':
		default:
			return false
		}
	}
	return true
}

type decodedJWT struct {
	rawHeader    []byte
	rawPayload   []byte
	header       map[string]interface{}
	payload      map[string]interface{}
	signature    []byte
	signingInput string
}

func decode(token string) (decodedJWT, error) {
	var d decodedJWT
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return d, fmt.Errorf("expected 3 parts, got %d", len(parts))
	}
	var err error
	if d.rawHeader, err = decodeSegment(parts[0]); err != nil {
		return d, fmt.Errorf("header: %w", err)
	}
	if d.rawPayload, err = decodeSegment(parts[1]); err != nil {
		return d, fmt.Errorf("payload: %w", err)
	}
	if d.signature, err = decodeSegment(parts[2]); err != nil {
		return d, fmt.Errorf("signature: %w", err)
	}
	if err = json.Unmarshal(d.rawHeader, &d.header); err != nil {
		return d, fmt.Errorf("header is not a JSON object: %w", err)
	}
	// A payload that isn't JSON is still printed; it just has no claims.
	_ = json.Unmarshal(d.rawPayload, &d.payload)
	d.signingInput = parts[0] + "." + parts[1]
	return d, nil
}

// decodeSegment decodes base64url with or without padding.
func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// indentJSON returns data indented, keeping the members in their original
// order, or data unchanged if it isn't JSON.
func indentJSON(data []byte) string {
	var out bytes.Buffer
	if err := json.Indent(&out, data, "", "  "); err != nil {
		return string(data)
	}
	return out.String()
}

// claimTimes describes the numeric date claims (RFC 7519 section 2).
func claimTimes(payload map[string]interface{}) []string {
	var lines []string
	now := time.Now()
	for _, name := range []string{"iat", "nbf", "exp"} {
		seconds, ok := payload[name].(float64)
		if !ok {
			continue
		}
		t := time.Unix(int64(seconds), 0)
		lines = append(lines, fmt.Sprintf("%s: %s (%s)", name, t.UTC().Format(time.RFC3339), relative(t, now)))
	}
	return lines
}

func relative(t, now time.Time) string {
	d := now.Sub(t).Round(time.Second)
	if d >= 0 {
		return d.String() + " ago"
	}
	return "in " + (-d).String()
}

// jwkThumbprint returns the RFC 7638 thumbprint of a JWK: the base64url
// SHA-256 hash of its required members in lexicographic order, with no
// whitespace.
func jwkThumbprint(jwk map[string]interface{}) (string, error) {
	var members []string
	switch jwk["kty"] {
	case "EC":
		members = []string{"crv", "kty", "x", "y"}
	case "RSA":
		members = []string{"e", "kty", "n"}
	case "OKP":
		members = []string{"crv", "kty", "x"}
	default:
		return "", fmt.Errorf("unsupported kty %v", jwk["kty"])
	}
	var b strings.Builder
	b.WriteString("{")
	for i, m := range members {
		v, ok := jwk[m].(string)
		if !ok {
			return "", fmt.Errorf("jwk is missing %s", m)
		}
		if i > 0 {
			b.WriteString(",")
		}
		key, _ := json.Marshal(m)
		value, _ := json.Marshal(v)
		b.Write(key)
		b.WriteString(":")
		b.Write(value)
	}
	b.WriteString("}")
	sum := sha256.Sum256([]byte(b.String()))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// verify checks a JWS signature with the public key in jwk.
func verify(alg string, jwk map[string]interface{}, signingInput string, signature []byte) error {
	switch alg {
	case "ES256", "ES384", "ES512":
		pub, err := ecPublicKey(jwk)
		if err != nil {
			return err
		}
		h := hashFor(alg)
		h.Write([]byte(signingInput))
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return fmt.Errorf("signature is %d bytes, want %d", len(signature), 2*size)
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(pub, h.Sum(nil), r, s) {
			return errors.New("signature does not match")
		}
		return nil
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		pub, err := rsaPublicKey(jwk)
		if err != nil {
			return err
		}
		h := hashFor(alg)
		h.Write([]byte(signingInput))
		hashID := map[string]crypto.Hash{"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512}[alg[2:]]
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(pub, hashID, h.Sum(nil), signature, nil)
		}
		return rsa.VerifyPKCS1v15(pub, hashID, h.Sum(nil), signature)
	default:
		return fmt.Errorf("unsupported alg %q", alg)
	}
}

func hashFor(alg string) hash.Hash {
	switch alg[2:] {
	case "384":
		return sha512.New384()
	case "512":
		return sha512.New()
	default:
		return sha256.New()
	}
}

func ecPublicKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
	crv, _ := jwk["crv"].(string)
	curve, ok := curves[crv]
	if !ok {
		return nil, fmt.Errorf("unsupported crv %q", crv)
	}
	x, err := jwkBytes(jwk, "x")
	if err != nil {
		return nil, err
	}
	y, err := jwkBytes(jwk, "y")
	if err != nil {
		return nil, err
	}
	point := append([]byte{4}, append(x, y...)...)
	return ecdsa.ParseUncompressedPublicKey(curve, point)
}

func rsaPublicKey(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	n, err := jwkBytes(jwk, "n")
	if err != nil {
		return nil, err
	}
	e, err := jwkBytes(jwk, "e")
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
}

func jwkBytes(jwk map[string]interface{}, member string) ([]byte, error) {
	s, ok := jwk[member].(string)
	if !ok {
		return nil, fmt.Errorf("jwk is missing %s", member)
	}
	b, err := decodeSegment(s)
	if err != nil {
		return nil, fmt.Errorf("jwk %s: %w", member, err)
	}
	return b, nil
}
