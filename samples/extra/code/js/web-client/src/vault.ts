// Browser vault: keys are generated with WebCrypto (crypto.subtle)
import { SignJWT } from 'jose';

const SHARE_ALGO: RsaHashedKeyGenParams = {
  name: 'RSA-OAEP',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: 'SHA-256',
};

export async function createVaultKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-CBC', length: 128 }, true, ['encrypt', 'decrypt']);
}

export async function createShareKeys(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(SHARE_ALGO, false, ['encrypt', 'decrypt']);
}

export async function deviceIdentity(): Promise<CryptoKeyPair> {
  return window.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
}

export async function sessionKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function fingerprint(data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-1', data);
}

export async function deviceToken(key: CryptoKey, deviceId: string): Promise<string> {
  return new SignJWT({ sub: deviceId }).setProtectedHeader({ alg: 'ES256' }).sign(key);
}
