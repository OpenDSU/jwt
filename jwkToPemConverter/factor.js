let asn = require('../../lib/asn1/asn1');
let crypto = require('crypto')
let BN = asn.bignum

let zero = new BN(0)
let one = new BN(1)
let two = new BN(2)

function rand(low, high) {
    let b;
    do {
        b = new BN(crypto.randomBytes(high.byteLength()))
    } while (b.cmp(low) <= 0 || b.cmp(high) >= 0)
    return b
}

function odd(n) {
    if (n.cmp(zero) === 0) {
        return zero
    }
    let r = n
    while (r.isEven()) {
        r = r.div(two)
    }
    return r
}

function rootOne(x, r, n) {
    let i = x.toRed(BN.red(n)).redPow(r).fromRed()
    let o = zero
    while (i.cmp(one) !== 0) {
        o = i
        i = i.mul(i).mod(n)
    }
    if (o.cmp(n.sub(one)) === 0) {
        return zero
    }
    return o
}

function factor(e, d, n) {
    let k = e.mul(d).sub(one)
    let r = odd(k)
    let y;
    do {
        y = rootOne(rand(two, n), r, n)
    } while (y.cmp(zero) === 0)

    let p = y.sub(one).gcd(n)
    return {
        p: p,
        q: n.div(p)
    }
}

module.exports = factor