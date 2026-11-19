# jwt

Decodes a JSON Web Token and prints its header and payload. Written for reading DPoP proofs (RFC 9449), but it decodes any JWS in compact form.

## Install

	go install github.com/cwarden/jwt@latest

or, from this directory:

	go install .

## Usage

Pass the token as an argument:

	jwt eyJ0eXAiOiJkcG9wK2p3dCIs...

or run `jwt` with no arguments, paste, and press Ctrl+D. Standard input is read to EOF, so the paste can be a block of request headers copied from mitmproxy or another proxy:

	$ jwt
	Paste a JWT or request headers, then press Ctrl+D:
	content-type:    application/json
	authorization:   DPoP 00Dxx0000000000!AQEA...
	dpop:            eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0y
	                 NTYiLCJ4IjoiSnFqUVMwY24xM1lEdDdiRmJwbU9BeFVkdnVrNGxhRzR4ZnlzdURRUEdyWSIs...
	user-agent:      force/dev (linux-amd64)

Everything that isn't a JWT is skipped: header names, authorization schemes such as `Bearer`, and access tokens that aren't JWTs. A JWT that the proxy wrapped onto continuation lines is joined back together. When the input holds more than one JWT, each is decoded in turn.

A header line also works as an argument:

	jwt 'DPoP: eyJ0eXAiOiJkcG9wK2p3dCIs...'

## Output

- The header and payload as indented JSON, with members in their original order.
- `iat`, `nbf`, and `exp` as UTC times, with how long ago or how far ahead each one is.
- The length of the signature in bytes.

When the header has a `jwk` member, as a DPoP proof does, it also prints:

- The JWK thumbprint (RFC 7638), which is the value a server compares with `dpop_jkt` and with the key a DPoP-bound token was issued to.
- Whether the signature verifies with that key. ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, and PS512 are supported.

## Example

	$ jwt 'DPoP: eyJ0eXAiOiJkcG9wK2p3dCIs...'
	Header:
	{
	  "alg": "ES256",
	  "jwk": {
	    "crv": "P-256",
	    "kty": "EC",
	    "x": "JqjQS0cn13YDt7bFbpmOAxUdvuk4laG4xfysuDQPGrY",
	    "y": "fK0vSbJ6_3RjLxG-7DwPLHpwlEDsRWIWSbxOIdcQwUQ"
	  },
	  "typ": "dpop+jwt"
	}

	Payload:
	{
	  "ath": "6cU3WVTHe6cT6Mkszt4K4Ozd5MtAPPDjOp-1WKaMuL4",
	  "htm": "POST",
	  "htu": "https://example.my.salesforce.com/services/data/v68.0/sobjects/Account",
	  "iat": 1795108215,
	  "jti": "EHFHE41EbRagW440IfHkUw",
	  "nonce": "eyJ7S_zExampleNonce"
	}

	iat: 2026-11-19T17:10:15Z (13s ago)

	Signature: 64 bytes
	JWK thumbprint: WDnBx5fHjfMJTRNxp2iXzS-hL5PIZk00yZazNjpmN24
	Signature check with the header's jwk: valid
