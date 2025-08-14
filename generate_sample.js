#!/usr/bin/env node

// Script to generate a valid COSE_Sign1 wrapped CWT token
// This creates proper CBOR encoding for testing

// Simple CBOR encoder for our specific needs
class CBOREncoder {
    constructor() {
        this.buffer = [];
    }

    // Encode positive integer
    encodeUint(value) {
        if (value < 24) {
            this.buffer.push(value);
        } else if (value < 256) {
            this.buffer.push(24, value);
        } else if (value < 65536) {
            this.buffer.push(25, value >> 8, value & 0xff);
        } else {
            this.buffer.push(26, 
                (value >> 24) & 0xff,
                (value >> 16) & 0xff, 
                (value >> 8) & 0xff,
                value & 0xff
            );
        }
    }

    // Encode negative integer
    encodeNegativeInt(value) {
        const absValue = Math.abs(value) - 1;
        if (absValue < 24) {
            this.buffer.push(0x20 | absValue);
        } else if (absValue < 256) {
            this.buffer.push(0x20 | 24, absValue);
        }
    }

    // Encode byte string
    encodeBytes(bytes) {
        this.buffer.push(0x40 | (bytes.length < 24 ? bytes.length : 24));
        if (bytes.length >= 24) {
            this.buffer.push(bytes.length);
        }
        this.buffer.push(...bytes);
    }

    // Encode text string
    encodeText(text) {
        const bytes = Array.from(new TextEncoder().encode(text));
        this.buffer.push(0x60 | (bytes.length < 24 ? bytes.length : 24));
        if (bytes.length >= 24) {
            this.buffer.push(bytes.length);
        }
        this.buffer.push(...bytes);
    }

    // Encode array
    encodeArray(length) {
        this.buffer.push(0x80 | (length < 24 ? length : 24));
        if (length >= 24) {
            this.buffer.push(length);
        }
    }

    // Encode map
    encodeMap(length) {
        this.buffer.push(0xa0 | (length < 24 ? length : 24));
        if (length >= 24) {
            this.buffer.push(length);
        }
    }

    // Get result as Uint8Array
    getBuffer() {
        return new Uint8Array(this.buffer);
    }
}

// Create CWT claims map
function createCWTClaims() {
    const encoder = new CBOREncoder();
    
    // Map with 9 entries (7 standard + 2 custom)
    encoder.encodeMap(9);
    
    // iss (1): "coap://as.example.com"
    encoder.encodeUint(1);
    encoder.encodeText("coap://as.example.com");
    
    // sub (2): "erikw"
    encoder.encodeUint(2);
    encoder.encodeText("erikw");
    
    // aud (3): "coap://light.example.com"
    encoder.encodeUint(3);
    encoder.encodeText("coap://light.example.com");
    
    // exp (4): 1444064944
    encoder.encodeUint(4);
    encoder.encodeUint(1444064944);
    
    // nbf (5): 1443944944
    encoder.encodeUint(5);
    encoder.encodeUint(1443944944);
    
    // iat (6): 1443944944
    encoder.encodeUint(6);
    encoder.encodeUint(1443944944);
    
    // cti (7): h'0b71'
    encoder.encodeUint(7);
    encoder.encodeBytes([0x0b, 0x71]);
    
    // Custom claim 100: "production"
    encoder.encodeUint(100);
    encoder.encodeText("production");
    
    // Custom claim 101: ["admin", "edit", "read"]
    encoder.encodeUint(101);
    encoder.encodeArray(3);
    encoder.encodeText("admin");
    encoder.encodeText("edit");
    encoder.encodeText("read");
    
    return encoder.getBuffer();
}

// Create protected headers
function createProtectedHeaders() {
    const encoder = new CBOREncoder();
    
    // Map with 1 entry: {1: -7} (alg: ES256)
    encoder.encodeMap(1);
    encoder.encodeUint(1);
    encoder.encodeNegativeInt(-7);
    
    return encoder.getBuffer();
}

// Create unprotected headers
function createUnprotectedHeaders() {
    const encoder = new CBOREncoder();
    
    // Map with 1 entry: {4: "test-key"} (kid)
    encoder.encodeMap(1);
    encoder.encodeUint(4);
    encoder.encodeText("test-key");
    
    return encoder.getBuffer();
}

// Create COSE_Sign1 structure
function createCOSESign1() {
    const protectedHeaders = createProtectedHeaders();
    const unprotectedHeaders = createUnprotectedHeaders();
    const payload = createCWTClaims();
    
    // Create dummy signature (64 bytes)
    const signature = new Array(64).fill(0).map((_, i) => 0x30 + (i % 10));
    
    const encoder = new CBOREncoder();
    
    // Array with 4 elements
    encoder.encodeArray(4);
    
    // Protected headers (as byte string)
    encoder.encodeBytes(Array.from(protectedHeaders));
    
    // Unprotected headers (as map) - encode directly
    encoder.buffer.push(...unprotectedHeaders);
    
    // Payload (as byte string)
    encoder.encodeBytes(Array.from(payload));
    
    // Signature (as byte string)
    encoder.encodeBytes(signature);
    
    return encoder.getBuffer();
}

// Convert to base64url
function toBase64Url(buffer) {
    const base64 = Buffer.from(buffer).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Generate the sample
function generateSample() {
    try {
        const coseSign1 = createCOSESign1();
        const base64url = toBase64Url(coseSign1);
        const hex = Array.from(coseSign1).map(b => b.toString(16).padStart(2, '0')).join('');
        
        console.log('Generated COSE_Sign1 CWT Sample:');
        console.log('=====================================');
        console.log('Base64URL:', base64url);
        console.log('');
        console.log('Hex:', hex);
        console.log('');
        console.log('Structure:');
        console.log('- Protected: {1: -7} (ES256)');
        console.log('- Unprotected: {4: "test-key"}');
        console.log('- Payload: CWT claims (iss, sub, aud, exp, nbf, iat, cti, custom claims)');
        console.log('- Signature: 64 bytes dummy data');
        
        return base64url;
        
    } catch (error) {
        console.error('Error generating sample:', error);
        return null;
    }
}

// Run if called directly
if (require.main === module) {
    generateSample();
}

module.exports = { generateSample };