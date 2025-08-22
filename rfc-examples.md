# RFC 8392 Official Examples

This file contains the official examples from RFC 8392 (CBOR Web Token) Appendix A in various formats for comprehensive testing.

## A.3 Example Signed CWT

From RFC 8392 Appendix A.3: "Example Signed CWT"

### Token Formats

#### Hex Format (original from RFC):
```
d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30
```

#### Base64URL Format:
```
0oRDoQEmoQRSQXN5bW1ldHJpY0VDRFNBMjU2WFCnAXVjb2FwOi8vYXMuZXhhbXBsZS5jb20CZWVyaWt3A3gYY29hcDovL2xpZ2h0LmV4YW1wbGUuY29tBBpWEq6wBRpWENnwBhpWENnwB0ILcVhAVCfB_yjSP7rR8pxMfGpVXmAdb6KfkXm8PXQ4usrKWs0IyNTU-WExaAxCmgH4WVHs7nQ6Urm2NjLFcgkSDhyeMA
```

### Token Structure
- **Type**: COSE_Sign1 (tag 18)
- **Algorithm**: ES256 (ECDSA with P-256 and SHA-256)
- **Key ID**: "AsymmetricECDSA256"
- **Length**: 175 bytes

### Claims Set
The payload contains these CWT claims:
- `1` (iss): "coap://as.example.com"
- `2` (sub): "erikw" 
- `3` (aud): "coap://light.example.com"
- `4` (exp): 1444064944
- `5` (nbf): 1443944944
- `6` (iat): 1443944944
- `7` (cti): h'0b71'

## ECDSA P-256 Public Key

From RFC 8392 Appendix A.2.3: "Elliptic Curve Digital Signature Algorithm (ECDSA) P-256 256-Bit COSE Key"

### Raw Coordinates
- **x**: `143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f`
- **y**: `60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9`
- **Curve**: P-256
- **Use**: Digital Signature

### Key Formats

#### 1. PEM Format (SPKI):
```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFDMpzOeGjkFpJ1mc9lo0884v/aVa
fspp7YkZo5TULw9g9/GngNing7+3ot1rJ5boEo27zvnT0WjblSmXGjbnuQ==
-----END PUBLIC KEY-----
```

#### 2. JWK Format (Minimal):
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "FDMpzOeGjkFpJ1mc9lo0884v_aVafspp7YkZo5TULw8",
  "y": "YPfxp4DYp4O_t6LdayeW6BKNu87509Fo25Uplxo257k"
}
```

#### 3. JWK Format (Full):
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "FDMpzOeGjkFpJ1mc9lo0884v_aVafspp7YkZo5TULw8",
  "y": "YPfxp4DYp4O_t6LdayeW6BKNu87509Fo25Uplxo257k",
  "use": "sig",
  "alg": "ES256",
  "kid": "AsymmetricECDSA256"
}
```

#### 4. Raw Format (Uncompressed Point):
```
04143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9
```

#### 5. Base64 Format:
```
BBQzKcznho5BaSdZnPZaNPPOL/2lWn7Kae2JGaOU1C8PYPfxp4DYp4O/t6LdayeW6BKNu87509Fo25Uplxo257k=
```

#### 6. DER Format (SPKI):
```
3059301306072a8648ce3d020106082a8648ce3d03010703420004143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9
```

## Test Instructions

### Expected Results
When using any of the public key formats above with the token, you should see:
- **COSE Type**: COSE_Sign1
- **Algorithm**: ES256  
- **Key ID**: AsymmetricECDSA256
- **Signature Verification**: **PASSED** ✅

### Browser Testing
1. Paste the Base64URL token into the CWT input field
2. Paste any of the public key formats into the verification key field  
3. All formats should successfully import and verify the signature

### Key Format Support
The implementation should support all these public key formats:
- ✅ PEM (SPKI) - standard format
- ✅ JWK (both minimal and full) - web standard  
- ✅ Hex (raw uncompressed point) - raw coordinates
- ✅ Base64 (raw uncompressed point) - base64 encoded raw
- ✅ DER (SPKI) - binary standard format

## A.4 Example MACed CWT

From RFC 8392 Appendix A.4: "Example MACed CWT"

### Token Formats

#### Hex Format (original from RFC):
```
d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200
```

#### Base64URL Format:
```
2D3RhEOhAQShBExTeW1tZXRyaWMyNTZYUKcBdWNvYXA6Ly9hcy5leGFtcGxlLmNvbQJlZXJpa3cDeBlqb2FwOi8vbGlnaHQuZXhhbXBsZS5jb20EGlYSrrAFGlYQ2fAGGlYQ2fAHQgtxSAkxAe9teJIA
```

### Token Structure
- **Type**: COSE_Mac0 (tag 17) wrapped in CWT tag (61)
- **Algorithm**: HMAC 256/64 (HMAC-SHA-256 with 64-bit truncation)
- **Key ID**: "Symmetric256"
- **Length**: 119 bytes

### Claims Set
Same as A.3:
- `1` (iss): "coap://as.example.com"
- `2` (sub): "erikw"
- `3` (aud): "coap://light.example.com"
- `4` (exp): 1444064944
- `5` (nbf): 1443944944
- `6` (iat): 1443944944
- `7` (cti): h'0b71'

## 256-Bit Symmetric Key (HMAC)

From RFC 8392 Appendix A.2.2: "256-Bit Symmetric Key"

### Raw Key Value
- **Hex**: `403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388`
- **Key ID**: "Symmetric256"
- **Algorithm**: HMAC 256/64

### Key Formats

#### 1. JWK Format (Minimal):
```json
{
  "kty": "oct",
  "k": "QDaX3oevZGEcHTKgXasP4fy3Fahqtjjx7JkZLXlWk4g"
}
```

#### 2. JWK Format (Full):
```json
{
  "kty": "oct",
  "k": "QDaX3oevZGEcHTKgXasP4fy3Fahqtjjx7JkZLXlWk4g",
  "alg": "HS256",
  "use": "sig",
  "kid": "Symmetric256"
}
```

#### 3. Hex Format:
```
403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388
```

#### 4. Base64 Format:
```
QDaX3oevZGEcHTKgXasP4fy3Fahqtjjx7JkZLXlWk4g=
```

#### 5. Base64URL Format:
```
QDaX3oevZGEcHTKgXasP4fy3Fahqtjjx7JkZLXlWk4g
```

#### 6. PEM Format (non-standard for symmetric keys):
```
-----BEGIN SYMMETRIC KEY-----
QDaX3oevZGEcHTKgXasP4fy3Fahqtjjx7JkZLXlWk4g=
-----END SYMMETRIC KEY-----
```

### Test Instructions

#### Expected Results
When using any of the symmetric key formats above with the MACed token, you should see:
- **COSE Type**: COSE_Mac0
- **Algorithm**: HMAC 256/64
- **Key ID**: Symmetric256
- **MAC Verification**: **PASSED** ✅

## A.5 Example Encrypted CWT

From RFC 8392 Appendix A.5: "Example Encrypted CWT"

### Token Formats

#### Hex Format (original from RFC):
```
d08343a1010aa2044c53796d6d6574726963313238054d99a0d7846e762c49ffe8a63e0b5858b918a11fd81e438b7f973d9e2e119bcb22424ba0f38a80f27562f400ee1d0d6c0fdb559c02421fd384fc2ebe22d7071378b0ea7428fff157444d45f7e6afcda1aae5f6495830c58627087fc5b4974f319a8707a635dd643b
```

#### Base64URL Format:
```
0INCocIAQqiBExTeW1tZXRyaWMxMjgFTZmg14RudiAxJ_-imPgtYWLkYoR_YHkOLf5c9ni4Rm8siQkK6DzioD5dWL0AO4dDWwP21WcAkIf04T8Lr4i1wcTeLD6dCj_8VdETUX35q_Noarmf2SVYMMWIYCB_xbSXTzGahwemNd1kOw
```

### Token Structure
- **Type**: COSE_Encrypt0 (tag 16)
- **Algorithm**: AES-CCM-16-64-128
- **Key ID**: "Symmetric128"
- **IV**: h'99a0d7846e762c49ffe8a63e0b'
- **Length**: 131 bytes

## 128-Bit Symmetric Key (AES-CCM)

From RFC 8392 Appendix A.2.1: "128-Bit Symmetric Key"

### Raw Key Value
- **Hex**: `231f4c4d4d3051fdc2ec0a3851d5b383`
- **Key ID**: "Symmetric128"
- **Algorithm**: AES-CCM-16-64-128

### Key Formats

#### 1. JWK Format (Minimal):
```json
{
  "kty": "oct",
  "k": "Ix9MTUM0Uf3C7Ao4UdWzgw"
}
```

#### 2. JWK Format (Full):
```json
{
  "kty": "oct",
  "k": "Ix9MTUM0Uf3C7Ao4UdWzgw",
  "alg": "A128GCM",
  "use": "enc",
  "kid": "Symmetric128"
}
```

#### 3. Hex Format:
```
231f4c4d4d3051fdc2ec0a3851d5b383
```

#### 4. Base64 Format:
```
Ix9MTUM0Uf3C7Ao4UdWzgw==
```

#### 5. Base64URL Format:
```
Ix9MTUM0Uf3C7Ao4UdWzgw
```

### Test Instructions

#### Expected Results
When using any of the symmetric key formats above with the encrypted token, you should see:
- **COSE Type**: COSE_Encrypt0
- **Algorithm**: AES-CCM-16-64-128
- **Key ID**: Symmetric128
- **Decryption**: **PASSED** ✅
- **Decrypted Claims**: Same as A.3

## A.6 Example Nested CWT

From RFC 8392 Appendix A.6: "Example Nested CWT"

### Token Formats

#### Hex Format (original from RFC):
```
d08343a1010aa2044c53796d6d6574726963313238054d4a0694c0e69ee6b5956655c7b258b7f6b0914f993de822cc47e5e57a188d7960b528a747446fe12f0e7de05650dec74724366763f167a29c002dfd15b34d8993391cf49bc91127f545dba8703d66f5b7f1ae91237503d371e6333df9708d78c4fb8a8386c8ff09dc49af768b23179deab78d96490a66d5724fb33900c60799d9872fac6da3bdb89043d67c2a05414ce331b5b8f1ed8ff7138f45905db2c4d5bc8045ab372bff142631610a7e0f677b7e9b0bc73adefdcee16d9d5d284c616abeab5d8c291ce0
```

#### Base64URL Format:
```
0INCocIAQqiBExTeW1tZXRyaWMxMjgFTUoGlMDmnjq1lWZVx7JYt_awkU-ZPegiLEfl5XoYjXlgtSimdHRG_hLw590FZQ3sdHJDZnZj8WeikDAi3hW_Q4mTkc9JvJESL_VF26hwPWb1t_GuJJDdQPTUeYzM935cI14xPuKo4xo_zAJ3Emvdosi5zepbeNlkkKZtVyT7M5AMYHmdmHL6xtoz22kEPWe8KgVBTONxtbjx7Y_3E49FkF2yxNW8gEWrNwUAGhwg
```

### Token Structure
- **Type**: COSE_Encrypt0 (tag 16) containing COSE_Sign1
- **Outer Algorithm**: AES-CCM-16-64-128
- **Inner Algorithm**: ES256
- **Demonstrates**: Nested protection (signed then encrypted)

## A.7 Example MACed CWT with Floating-Point Value

From RFC 8392 Appendix A.7: "Example MACed CWT with a Floating-Point Value"

### Token Formats

#### Hex Format (original from RFC):
```
d18443a10104a1044c53796d6d65747269633235364ba106fb41d584367c20000048b8816f34c0542892
```

#### Base64URL Format:
```
0YRDoQEEoQRMU3ltbWV0cmljMjU2S6EG-0HVhDZ8IAAASLiBbzTAVCiS
```

### Token Structure
- **Type**: COSE_Mac0 (tag 17)
- **Algorithm**: HMAC 256/64
- **Key ID**: "Symmetric256"
- **Special Feature**: Floating-point iat claim (1443944944.5)

### Claims Set
- `6` (iat): 1443944944.5 (floating-point value)

## Notes

- These are the **official RFC 8392 examples** - not test data
- Each example demonstrates different COSE protection methods
- All examples use the same claims set (except A.7 which has only iat)
- The nested example (A.6) shows how to combine signing and encryption
- All key formats should be supported for comprehensive testing

## References

- [RFC 8392 - CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392)
- [RFC 8152 - CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)