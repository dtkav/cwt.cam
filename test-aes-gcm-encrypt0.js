// Test script for COSE_Encrypt0 AES-GCM support
// Algorithm 1: AES-GCM mode w/ 128-bit key, 128-bit tag

// Create a test COSE_Encrypt0 token using AES-GCM (algorithm 1)
// This should work with Web Crypto API unlike AES-CCM

const crypto = require('crypto');

// Test key for AES-128-GCM (16 bytes = 128 bits)
const aes_key_hex = "231f4c4d4d3051fdc2ec0a3851d5b383";
const aes_key_bytes = Buffer.from(aes_key_hex, 'hex');

// Test IV/nonce for AES-GCM (12 bytes = 96 bits, standard for GCM)
const iv_hex = "99a0d7846e762c49ffe8a63e";
const iv_bytes = Buffer.from(iv_hex, 'hex');

// Test claims set (same as RFC examples)
const claims_set = {
    1: "coap://as.example.com",        // iss
    2: "erikw",                       // sub  
    3: "coap://light.example.com",    // aud
    4: 1444064944,                    // exp
    5: 1443944944,                    // nbf
    6: 1443944944,                    // iat
    7: Buffer.from([0x0b, 0x71])      // cti
};

console.log("Creating COSE_Encrypt0 test with AES-GCM...");
console.log("Algorithm: AES-GCM-128 (algorithm 1)");
console.log("Key (hex):", aes_key_hex);
console.log("IV (hex):", iv_hex);

// Encode the claims as CBOR (manual for this test)
const cbor = require('cbor');
const plaintext = cbor.encode(claims_set);

console.log("Plaintext length:", plaintext.length, "bytes");
console.log("Plaintext (hex):", plaintext.toString('hex'));

// Create COSE_Encrypt0 structure manually
// COSE_Encrypt0 = [protected_headers, unprotected_headers, ciphertext]

// Protected headers: {alg: 1} (AES-GCM-128)
const protected_headers = Buffer.from(cbor.encode({1: 1}));

// Unprotected headers: {kid: "Symmetric128", iv: iv_bytes}
const unprotected_headers = {
    4: Buffer.from("Symmetric128", 'utf8'),  // kid
    5: iv_bytes                              // iv
};

console.log("Protected headers (hex):", protected_headers.toString('hex'));
console.log("Unprotected headers:", unprotected_headers);

// Create Enc_structure for AES-GCM Additional Authenticated Data (AAD)
// Enc_structure = ["Encrypt0", protected_headers, external_aad]
const enc_structure = cbor.encode(["Encrypt0", protected_headers, Buffer.alloc(0)]);

console.log("Enc_structure (hex):", enc_structure.toString('hex'));

// Encrypt with AES-GCM
try {
    const cipher = crypto.createCipheriv('aes-128-gcm', aes_key_bytes, iv_bytes);
    cipher.setAAD(enc_structure);
    
    let ciphertext = cipher.update(plaintext);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const auth_tag = cipher.getAuthTag();
    
    // For COSE, we append the auth tag to the ciphertext
    const cose_ciphertext = Buffer.concat([ciphertext, auth_tag]);
    
    console.log("Ciphertext (hex):", ciphertext.toString('hex'));
    console.log("Auth tag (hex):", auth_tag.toString('hex'));
    console.log("COSE ciphertext (hex):", cose_ciphertext.toString('hex'));
    
    // Create the full COSE_Encrypt0 array
    const cose_encrypt0 = [
        protected_headers,
        unprotected_headers,
        cose_ciphertext
    ];
    
    // Encode as CBOR
    const cose_encrypt0_cbor = cbor.encode(cose_encrypt0);
    
    // Add COSE_Encrypt0 tag (16)
    const tagged_cose = cbor.encode(new cbor.Tagged(16, cose_encrypt0));
    
    console.log("\\nFinal COSE_Encrypt0 (hex):", tagged_cose.toString('hex'));
    console.log("Final COSE_Encrypt0 (base64url):", tagged_cose.toString('base64url'));
    
    console.log("\\n=== TEST DATA FOR CWT.cam ===");
    console.log("Token (Base64URL):", tagged_cose.toString('base64url'));
    console.log("Key (hex):", aes_key_hex);
    console.log("Expected Algorithm: AES-GCM-128 (algorithm 1)");
    console.log("Expected Key ID: Symmetric128");
    console.log("Should decrypt successfully with Web Crypto API ✅");
    
} catch (error) {
    console.error("Error creating test token:", error);
}