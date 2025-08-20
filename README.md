# CWT.cam - CBOR Web Token Debugger

CWT.cam is like [jwt.io](https://jwt.io) but for CBOR Web Tokens (CWTs).

You can use it to decode, inspect, and validate CWTs as defined by [RFC 8392](https://tools.ietf.org/rfc/rfc8392.txt).

## Features

- **CWT Token Decoding**: Decode base64url or hex-encoded CWT tokens
- **COSE Structure Analysis**: Inspect COSE_Sign1 wrapped tokens with algorithm and key ID details
- **Claims Visualization**: View CWT claims with automatic mapping to RFC 8392 standard names
- **Signature Verification**: Validate CWT signatures using public keys (PEM, JWK, Hex, Base64 formats)
- **Claims Registry**: Built-in RFC 8392 standard claims (1-7) and IANA extended claims
- **Custom Claims**: Add and manage custom claim definitions with inline editing
- **Schema Export**: Export claim definitions as RFC 8392 compliant CDDL format
