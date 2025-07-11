let crypto = require('crypto');
let formatEcdsa = require('./ecdsa-sig-formatter');
let util = require('util');

let MSG_INVALID_ALGORITHM = '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'
let MSG_INVALID_TYPE = 'secret must be a string or buffer';
let MSG_INVALID_VERIFIER_KEY = 'key must be a string or a buffer';
let MSG_INVALID_SIGNER_KEY = 'key must be a string, a buffer or an object';

let supportsKeyObjects = typeof crypto.createPublicKey === 'function';
if (supportsKeyObjects) {
    MSG_INVALID_VERIFIER_KEY += ' or a KeyObject';
    MSG_INVALID_TYPE += 'or a KeyObject';
}

function checkIsPublicKey(key) {
    if (Buffer.isBuffer(key)) {
        return;
    }

    if (typeof key === 'string') {
        return;
    }

    if (!supportsKeyObjects) {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
    }

    if (typeof key !== 'object') {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
    }

    if (typeof key.type !== 'string') {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
    }

    if (typeof key.asymmetricKeyType !== 'string') {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
    }

    if (typeof key.export !== 'function') {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
    }
}

function checkIsPrivateKey(key) {
    if (Buffer.isBuffer(key)) {
        return;
    }

    if (typeof key === 'string') {
        return;
    }

    if (typeof key === 'object') {
        return;
    }

    throw typeError(MSG_INVALID_SIGNER_KEY);
}

function checkIsSecretKey(key) {
    if (Buffer.isBuffer(key)) {
        return;
    }

    if (typeof key === 'string') {
        return key;
    }

    if (!supportsKeyObjects) {
        throw typeError(MSG_INVALID_TYPE);
    }

    if (typeof key !== 'object') {
        throw typeError(MSG_INVALID_TYPE);
    }

    if (key.type !== 'secret') {
        throw typeError(MSG_INVALID_TYPE);
    }

    if (typeof key.export !== 'function') {
        throw typeError(MSG_INVALID_TYPE);
    }
}

function fromBase64(base64) {
    return base64
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function toBase64(base64url) {
    base64url = base64url.toString();

    let padding = 4 - base64url.length % 4;
    if (padding !== 4) {
        for (let i = 0; i < padding; ++i) {
            base64url += '=';
        }
    }

    return base64url
        .replace(/-/g, '+')
        .replace(/_/g, '/');
}

function typeError(template) {
    let args = [].slice.call(arguments, 1);
    let errMsg = util.format.bind(util, template).apply(null, args);
    return new TypeError(errMsg);
}

function bufferOrString(obj) {
    return Buffer.isBuffer(obj) || typeof obj === 'string';
}

function normalizeInput(thing) {
    if (!bufferOrString(thing))
        thing = JSON.stringify(thing);
    return thing;
}

function createHmacSigner(bits) {
    return function sign(thing, secret) {
        checkIsSecretKey(secret);
        thing = normalizeInput(thing);
        let hmac = crypto.createHmac('sha' + bits, secret);
        let sig = (hmac.update(thing), hmac.digest('base64'))
        return fromBase64(sig);
    }
}

function createHmacVerifier(bits) {
    return function verify(thing, signature, secret) {
        let computedSig = createHmacSigner(bits)(thing, secret);
        return Buffer.from(signature).equals(Buffer.from(computedSig));
    }
}

function createKeySigner(bits) {
    return function sign(thing, privateKey) {
        checkIsPrivateKey(privateKey);
        thing = normalizeInput(thing);
        // Even though we are specifying "RSA" here, this works with ECDSA
        // keys as well.
        let signer = crypto.createSign('RSA-SHA' + bits);
        let sig = (signer.update(thing), signer.sign(privateKey, 'base64'));
        return fromBase64(sig);
    }
}

function createKeyVerifier(bits) {
    return function verify(thing, signature, publicKey) {
        checkIsPublicKey(publicKey);
        thing = normalizeInput(thing);
        signature = toBase64(signature);
        let verifier = crypto.createVerify('RSA-SHA' + bits);
        verifier.update(thing);
        return verifier.verify(publicKey, signature, 'base64');
    }
}

function createPSSKeySigner(bits) {
    return function sign(thing, privateKey) {
        checkIsPrivateKey(privateKey);
        thing = normalizeInput(thing);
        let signer = crypto.createSign('RSA-SHA' + bits);
        let sig = (signer.update(thing), signer.sign({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        }, 'base64'));
        return fromBase64(sig);
    }
}

function createPSSKeyVerifier(bits) {
    return function verify(thing, signature, publicKey) {
        checkIsPublicKey(publicKey);
        thing = normalizeInput(thing);
        signature = toBase64(signature);
        let verifier = crypto.createVerify('RSA-SHA' + bits);
        verifier.update(thing);
        return verifier.verify({
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        }, signature, 'base64');
    }
}

function createECDSASigner(bits) {
    let inner = createKeySigner(bits);
    return function sign() {
        let signature = inner.apply(null, arguments);
        signature = formatEcdsa.derToJose(signature, 'ES' + bits);
        return signature;
    };
}

function createECDSAVerifer(bits) {
    let inner = createKeyVerifier(bits);
    return function verify(thing, signature, publicKey) {
        signature = formatEcdsa.joseToDer(signature, 'ES' + bits).toString('base64');
        let result = inner(thing, signature, publicKey);
        return result;
    };
}

function createNoneSigner() {
    return function sign() {
        return '';
    }
}

function createNoneVerifier() {
    return function verify(thing, signature) {
        return signature === '';
    }
}

module.exports = function jwa(algorithm) {
    let signerFactories = {
        hs: createHmacSigner,
        rs: createKeySigner,
        ps: createPSSKeySigner,
        es: createECDSASigner,
        none: createNoneSigner,
    }
    let verifierFactories = {
        hs: createHmacVerifier,
        rs: createKeyVerifier,
        ps: createPSSKeyVerifier,
        es: createECDSAVerifer,
        none: createNoneVerifier,
    }
    let match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/);
    if (!match)
        throw typeError(MSG_INVALID_ALGORITHM, algorithm);
    let algo = (match[1] || match[3]).toLowerCase();
    let bits = match[2];

    return {
        sign: signerFactories[algo](bits),
        verify: verifierFactories[algo](bits),
    }
};