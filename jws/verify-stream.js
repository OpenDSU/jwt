let DataStream = require('./data-stream');
let jwa = require('../jwa');
let Stream = require('stream');
let toString = require('./tostring');
let util = require('util');
let JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;

function isObject(thing) {
    return Object.prototype.toString.call(thing) === '[object Object]';
}

function safeJsonParse(thing) {
    if (isObject(thing))
        return thing;
    try {
        return JSON.parse(thing);
    } catch (e) {
        return undefined;
    }
}

function headerFromJWS(jwsSig) {
    let encodedHeader = jwsSig.split('.', 1)[0];
    return safeJsonParse($$.Buffer.from(encodedHeader, 'base64').toString('binary'));
}

function securedInputFromJWS(jwsSig) {
    return jwsSig.split('.', 2).join('.');
}

function signatureFromJWS(jwsSig) {
    return jwsSig.split('.')[2];
}

function payloadFromJWS(jwsSig, encoding) {
    encoding = encoding || 'utf8';
    let payload = jwsSig.split('.')[1];
    return $$.Buffer.from(payload, 'base64').toString(encoding);
}

function isValidJws(string) {
    return JWS_REGEX.test(string) && !!headerFromJWS(string);
}

function jwsVerify(jwsSig, algorithm, secretOrKey) {
    if (!algorithm) {
        let err = new Error("Missing algorithm parameter for jws.verify");
        err.code = "MISSING_ALGORITHM";
        throw err;
    }
    jwsSig = toString(jwsSig);
    let signature = signatureFromJWS(jwsSig);
    let securedInput = securedInputFromJWS(jwsSig);
    let algo = jwa(algorithm);
    return algo.verify(securedInput, signature, secretOrKey);
}

function jwsDecode(jwsSig, opts) {
    opts = opts || {};
    jwsSig = toString(jwsSig);

    if (!isValidJws(jwsSig))
        return null;

    let header = headerFromJWS(jwsSig);

    if (!header)
        return null;

    let payload = payloadFromJWS(jwsSig);
    if (header.typ === 'JWT' || opts.json)
        payload = JSON.parse(payload, opts.encoding);

    return {
        header: header,
        payload: payload,
        signature: signatureFromJWS(jwsSig)
    };
}

function VerifyStream(opts) {
    opts = opts || {};
    let secretOrKey = opts.secret || opts.publicKey || opts.key;
    let secretStream = new DataStream(secretOrKey);
    this.readable = true;
    this.algorithm = opts.algorithm;
    this.encoding = opts.encoding;
    this.secret = this.publicKey = this.key = secretStream;
    this.signature = new DataStream(opts.signature);
    this.secret.once('close', function () {
        if (!this.signature.writable && this.readable)
            this.verify();
    }.bind(this));

    this.signature.once('close', function () {
        if (!this.secret.writable && this.readable)
            this.verify();
    }.bind(this));
}

util.inherits(VerifyStream, Stream);
VerifyStream.prototype.verify = function verify() {
    try {
        let valid = jwsVerify(this.signature.buffer, this.algorithm, this.key.buffer);
        let obj = jwsDecode(this.signature.buffer, this.encoding);
        this.emit('done', valid, obj);
        this.emit('data', valid);
        this.emit('end');
        this.readable = false;
        return valid;
    } catch (e) {
        this.readable = false;
        this.emit('error', e);
        this.emit('close');
    }
};

VerifyStream.decode = jwsDecode;
VerifyStream.isValid = isValidJws;
VerifyStream.verify = jwsVerify;

module.exports = VerifyStream;