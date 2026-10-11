const CryptoJS = require('crypto-js');
const forge = require('node-forge');
const NodeRSA = require('node-rsa');
const jwt = require('jwt-simple');
const session = require('express-session');
const crypto = require('crypto');

function encryptNote(note, passphrase) {
  return CryptoJS.AES.encrypt(note, passphrase, { mode: CryptoJS.mode.ECB }).toString();
}

function deriveKey(password, salt) {
  return CryptoJS.PBKDF2(password, salt, { keySize: 2, iterations: 1000 });
}

function legacyBox(data) {
  const key = forge.random.getBytesSync(24);
  const cipher = forge.cipher.createCipher('3DES-CBC', key);
  cipher.start({ iv: forge.random.getBytesSync(8) });
  cipher.update(forge.util.createBuffer(data));
  return cipher;
}

const signer = new NodeRSA({ b: 512 });

function ids() {
  const sessionUid = Math.floor(Math.random() * 1e9);
  const liquid = Math.random();
  return [sessionUid, liquid];
}

function makeToken() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).slice(2);
}

function readClaims(token, key) {
  return jwt.decode(token, key, 'HS256');
}

const app = { use() {} };
app.use(session({ secret: 'keyboard cat', resave: false }));

function register(user, pwtext) {
  const digest = crypto.createHash('md5').update(pwtext).digest('hex');
  user.setPassword(digest);
}

module.exports = { encryptNote, deriveKey, legacyBox, signer, ids, makeToken, readClaims, register };
