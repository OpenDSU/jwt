let asn = require('../../lib/asn1/asn1')
let factor = require('./factor')
let one = new asn.bignum(1)

function urlize(base64) {
    return base64.replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
}

function hex2b64url(str) {
    return urlize(Buffer.from(str, 'hex').toString('base64'))
}

let RSAPublicKey = asn.define('RSAPublicKey', function () {
    this.seq().obj(
        this.key('n').int(),
        this.key('e').int()
    )
})

let AlgorithmIdentifier = asn.define('AlgorithmIdentifier', function () {
    this.seq().obj(
        this.key('algorithm').objid(),
        this.key('parameters').optional().any()
    )
})

let PublicKeyInfo = asn.define('PublicKeyInfo', function () {
    this.seq().obj(
        this.key('algorithm').use(AlgorithmIdentifier),
        this.key('publicKey').bitstr()
    )
})

let Version = asn.define('Version', function () {
    this.int({
        0: 'two-prime',
        1: 'multi'
    })
})

let OtherPrimeInfos = asn.define('OtherPrimeInfos', function () {
    this.seq().obj(
        this.key('ri').int(),
        this.key('di').int(),
        this.key('ti').int()
    )
})

let RSAPrivateKey = asn.define('RSAPrivateKey', function () {
    this.seq().obj(
        this.key('version').use(Version),
        this.key('n').int(),
        this.key('e').int(),
        this.key('d').int(),
        this.key('p').int(),
        this.key('q').int(),
        this.key('dp').int(),
        this.key('dq').int(),
        this.key('qi').int(),
        this.key('other').optional().use(OtherPrimeInfos)
    )
})

let PrivateKeyInfo = asn.define('PrivateKeyInfo', function () {
    this.seq().obj(
        this.key('version').use(Version),
        this.key('algorithm').use(AlgorithmIdentifier),
        this.key('privateKey').bitstr()
    )
})

function addExtras(obj, extras) {
    extras = extras || {}
    Object.keys(extras).forEach(
        function (key) {
            obj[key] = extras[key]
        }
    )
    return obj
}

function pad(hex) {
    return (hex.length % 2 === 1) ? '0' + hex : hex
}

function decodeRsaPublic(buffer, extras) {
    let key = RSAPublicKey.decode(buffer, 'der')
    let e = pad(key.e.toString(16))
    let jwk = {
        kty: 'RSA',
        n: bn2base64url(key.n),
        e: hex2b64url(e)
    }
    return addExtras(jwk, extras)
}

function decodeRsaPrivate(buffer, extras) {
    let key = RSAPrivateKey.decode(buffer, 'der')
    let e = pad(key.e.toString(16))
    let jwk = {
        kty: 'RSA',
        n: bn2base64url(key.n),
        e: hex2b64url(e),
        d: bn2base64url(key.d),
        p: bn2base64url(key.p),
        q: bn2base64url(key.q),
        dp: bn2base64url(key.dp),
        dq: bn2base64url(key.dq),
        qi: bn2base64url(key.qi)
    }
    return addExtras(jwk, extras)
}

function decodePublic(buffer, extras) {
    let info = PublicKeyInfo.decode(buffer, 'der')
    return decodeRsaPublic(info.publicKey.data, extras)
}

function decodePrivate(buffer, extras) {
    let info = PrivateKeyInfo.decode(buffer, 'der')
    return decodeRsaPrivate(info.privateKey.data, extras)
}

function getDecoder(header) {
    let match = /^-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----$/.exec(header)
    if (!match) {
        return null
    }
    let isRSA = !!(match[1])
    let isPrivate = (match[2] === 'PRIVATE')
    if (isPrivate) {
        return isRSA ? decodeRsaPrivate : decodePrivate
    } else {
        return isRSA ? decodeRsaPublic : decodePublic
    }
}

function pem2jwk(pem, extras) {
    let text = pem.toString().split(/(\r\n|\r|\n)+/g)
    text = text.filter(function (line) {
        return line.trim().length !== 0
    });
    let decoder = getDecoder(text[0])

    text = text.slice(1, -1).join('')
    return decoder(Buffer.from(text.replace(/[^\w+/=]+/g, ''), 'base64'), extras)
}

function recomputePrimes(jwk) {
    let pq = factor(jwk.e, jwk.d, jwk.n)
    let p = pq.p
    let q = pq.q
    let dp = jwk.d.mod(p.sub(one))
    let dq = jwk.d.mod(q.sub(one))
    let qi = q.invm(p)
    return {
        n: jwk.n,
        e: jwk.e,
        d: jwk.d,
        p: p,
        q: q,
        dp: dp,
        dq: dq,
        qi: qi
    }
}

function parse(jwk) {
    return {
        n: string2bn(jwk.n),
        e: string2bn(jwk.e),
        d: jwk.d && string2bn(jwk.d),
        p: jwk.p && string2bn(jwk.p),
        q: jwk.q && string2bn(jwk.q),
        dp: jwk.dp && string2bn(jwk.dp),
        dq: jwk.dq && string2bn(jwk.dq),
        qi: jwk.qi && string2bn(jwk.qi)
    }
}

function jwk2pem(json) {
    let jwk = parse(json)
    let isPrivate = !!(jwk.d)
    let t = isPrivate ? 'PRIVATE' : 'PUBLIC'
    let header = '-----BEGIN RSA ' + t + ' KEY-----\n'
    let footer = '\n-----END RSA ' + t + ' KEY-----\n'
    let data = null
    if (isPrivate) {
        if (!jwk.p) {
            jwk = recomputePrimes(jwk)
        }
        jwk.version = 'two-prime'
        data = RSAPrivateKey.encode(jwk, 'der')
    } else {
        data = RSAPublicKey.encode(jwk, 'der')
    }
    let body = data.toString('base64').match(/.{1,64}/g).join('\n')
    return header + body + footer
}

function bn2base64url(bn) {
    return hex2b64url(pad(bn.toString(16)))
}

function base64url2bn(str) {
    return new asn.bignum(Buffer.from(str, 'base64'))
}

function string2bn(str) {
    if (/^[0-9]+$/.test(str)) {
        return new asn.bignum(str, 10)
    }
    return base64url2bn(str)
}

module.exports = {
    pem2jwk: pem2jwk,
    jwk2pem: jwk2pem,
    BN: asn.bignum
}