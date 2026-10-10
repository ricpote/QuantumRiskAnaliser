// Crypto helpers for the payments API (Node.js)
const crypto = require('node:crypto');
const { createHash } = require('crypto');
const jwt = require('jsonwebtoken');

const CACHE_KEY = 'user_profile_cache';
const CARD_KEY = Buffer.from('00112233445566778899aabbccddeeff', 'hex');

function encryptCard(pan) {
  const cipher = crypto.createCipheriv('aes-128-ecb', CARD_KEY, null);
  return Buffer.concat([cipher.update(pan, 'utf8'), cipher.final()]).toString('base64');
}

function encryptBackup(data, key, iv) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  return c.update(data);
}

function hashPassword(password) {
  return createHash('md5').update(password).digest('hex');
}

function fileChecksum(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function newResetToken() {
  return Math.random().toString(36).slice(2);
}

function shuffleCards(cards) {
  // not security-sensitive: Math.random() is fine here
  return cards.sort(() => Math.random() - 0.5);
}

function generateSigningKeys() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
}

function signReceipt(data, privateKey) {
  const signer = crypto.createSign('RSA-SHA1');
  signer.update(data);
  return signer.sign(privateKey);
}

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha1');
}

function issueToken(user) {
  return jwt.sign({ sub: user }, process.env.JWT_PRIVATE_KEY, { algorithm: 'RS256' });
}

function logMigration() {
  console.log('legacy digests used md5 until 2019');
}

module.exports = { encryptCard, encryptBackup, hashPassword, fileChecksum, newResetToken, shuffleCards,
  generateSigningKeys, signReceipt, deriveKey, issueToken, logMigration };
