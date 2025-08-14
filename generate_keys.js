#!/usr/bin/env node

// Generate test keys for CWT signature verification
const crypto = require('crypto');

function generateES256KeyPair() {
    // Generate ECDSA P-256 key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1', // P-256
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8', 
            format: 'pem'
        }
    });

    // Also export as JWK format
    const publicKeyObject = crypto.createPublicKey(publicKey);
    const privateKeyObject = crypto.createPrivateKey(privateKey);

    // Extract raw coordinates for JWK
    const publicKeyBuffer = publicKeyObject.export({ format: 'der', type: 'spki' });
    const privateKeyBuffer = privateKeyObject.export({ format: 'der', type: 'pkcs8' });

    // For P-256, public key is 65 bytes (04 + 32 bytes x + 32 bytes y)
    // Extract from DER encoding (last 65 bytes of SPKI)
    const publicKeyRaw = publicKeyBuffer.slice(-65);
    const x = publicKeyRaw.slice(1, 33);
    const y = publicKeyRaw.slice(33, 65);

    const publicJWK = {
        kty: 'EC',
        crv: 'P-256',
        x: x.toString('base64url'),
        y: y.toString('base64url'),
        use: 'sig',
        kid: 'test-key'
    };

    return {
        publicKeyPEM: publicKey,
        privateKeyPEM: privateKey,
        publicKeyJWK: publicJWK,
        publicKeyHex: publicKeyRaw.toString('hex'),
        publicKeyBase64: publicKeyRaw.toString('base64')
    };
}

function generateHMACKey() {
    const secret = crypto.randomBytes(32); // 256-bit key
    
    return {
        secretHex: secret.toString('hex'),
        secretBase64: secret.toString('base64'),
        secretBase64Url: secret.toString('base64url')
    };
}

function displayKeys() {
    console.log('🔑 Test Keys for CWT Verification');
    console.log('================================');
    console.log();
    
    // Generate ES256 keys
    console.log('📋 ES256 (ECDSA P-256) Keys:');
    console.log('----------------------------');
    const es256Keys = generateES256KeyPair();
    
    console.log('Public Key (PEM):');
    console.log(es256Keys.publicKeyPEM);
    console.log();
    
    console.log('Public Key (JWK):');
    console.log(JSON.stringify(es256Keys.publicKeyJWK, null, 2));
    console.log();
    
    console.log('Public Key (Hex):');
    console.log(es256Keys.publicKeyHex);
    console.log();
    
    console.log('Public Key (Base64):');
    console.log(es256Keys.publicKeyBase64);
    console.log();
    
    // Generate HMAC key
    console.log('📋 HMAC-SHA256 Secret:');
    console.log('----------------------');
    const hmacKeys = generateHMACKey();
    
    console.log('Secret (Hex):');
    console.log(hmacKeys.secretHex);
    console.log();
    
    console.log('Secret (Base64):');
    console.log(hmacKeys.secretBase64);
    console.log();
    
    console.log('📝 Usage Instructions:');
    console.log('---------------------');
    console.log('1. Load the sample CWT in the debugger');
    console.log('2. Click "Add Key" in the Signature Status section');
    console.log('3. Select "ECDSA P-256 (ES256)" as key type');
    console.log('4. Choose your preferred format (PEM, JWK, Hex, or Base64)');
    console.log('5. Paste the corresponding public key');
    console.log('6. Click "Save Key" then "Verify Signature"');
    console.log();
    console.log('Note: Since this is a demo with dummy signatures,');
    console.log('verification will randomly succeed/fail for testing purposes.');
}

if (require.main === module) {
    displayKeys();
}

module.exports = { generateES256KeyPair, generateHMACKey };