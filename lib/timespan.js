module.exports = function (time, iat) {
    const timestamp = iat || Math.floor(Date.now() / 1000);

    if (typeof time === 'number') {
        return timestamp + time;
    }
};