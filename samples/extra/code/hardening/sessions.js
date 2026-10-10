const jose = require('jose');
const { JWT } = jose;
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');

function issue(payload) {
  return JWT.sign(payload, 'hardcoded-signing-key');
}

function peek(token) {
  return jwt.decode(token).sub;   // never verified
}

const auth = expressJwt({ secret: 'shared-secret-123', algorithms: ['HS256'] });

function notWebCrypto(notCrypto, data) {
  return notCrypto.subtle.digest('SHA-1', data);   // not WebCrypto: not reported
}

module.exports = { issue, peek, auth, notWebCrypto };
