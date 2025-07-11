let DataStream = require('./data-stream');
let jwa = require('../jwa');
let Stream = require('stream');
let toString = require('./tostring');
let util = require('util');

function base64url(string, encoding) {
    return Buffer
        .from(string, encoding)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function jwsSecuredInput(header, payload, encoding) {
    encoding = encoding || 'utf8';
    let encodedHeader = base64url(toString(header), 'binary');
    let encodedPayload = base64url(toString(payload), encoding);
    return util.format('%s.%s', encodedHeader, encodedPayload);
}

function jwsSign(opts) {
    let header = opts.header;
    let payload = opts.payload;
    let secretOrKey = opts.secret || opts.privateKey;
    let encoding = opts.encoding;
    let algo = jwa(header.alg);
    let securedInput = jwsSecuredInput(header, payload, encoding);
    let signature = algo.sign(securedInput, secretOrKey);
    return util.format('%s.%s', securedInput, signature);
}

function SignStream(opts) {
    let secret = opts.secret || opts.privateKey || opts.key;
    let secretStream = new DataStream(secret);
    this.readable = true;
    this.header = opts.header;
    this.encoding = opts.encoding;
    this.secret = this.privateKey = this.key = secretStream;
    this.payload = new DataStream(opts.payload);
    this.secret.once('close', function () {
        if (!this.payload.writable && this.readable)
            this.sign();
    }.bind(this));

    this.payload.once('close', function () {
        if (!this.secret.writable && this.readable)
            this.sign();
    }.bind(this));
}

util.inherits(SignStream, Stream);

SignStream.prototype.sign = function sign() {
    try {
        let signature = jwsSign({
            header: this.header,
            payload: this.payload.buffer,
            secret: this.secret.buffer,
            encoding: this.encoding
        });
        this.emit('done', signature);
        this.emit('data', signature);
        this.emit('end');
        this.readable = false;
        return signature;
    } catch (e) {
        this.readable = false;
        this.emit('error', e);
        this.emit('close');
    }
};

SignStream.sign = jwsSign;

module.exports = SignStream;