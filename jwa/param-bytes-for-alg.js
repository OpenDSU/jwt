'use strict';

function getParamSize(keySize) {
    let result = ((keySize / 8) | 0) + (keySize % 8 === 0 ? 0 : 1);
    return result;
}

let paramBytesForAlg = {
    ES256: getParamSize(256),
    ES384: getParamSize(384),
    ES512: getParamSize(521)
};

function getParamBytesForAlg(alg) {
    let paramBytes = paramBytesForAlg[alg];
    if (paramBytes) {
        return paramBytes;
    }

    throw new Error('Unknown algorithm "' + alg + '"');
}

module.exports = getParamBytesForAlg;