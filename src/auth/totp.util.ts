import { createHmac, randomBytes } from 'crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

type TotpOptions = {
  timestampMs?: number;
  stepSeconds?: number;
  digits?: number;
};

function normalizeBase32(input: string): string {
  return String(input || '')
    .toUpperCase()
    .replace(/=+$/g, '')
    .replace(/[^A-Z2-7]/g, '');
}

function encodeBase32(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function decodeBase32(base32: string): Buffer {
  const normalized = normalizeBase32(base32);
  if (!normalized) return Buffer.alloc(0);

  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const ch of normalized) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

function hotp(secret: Buffer, counter: number, digits: number): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuffer.writeUInt32BE(counter >>> 0, 4);

  const hmac = createHmac('sha1', secret).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const mod = 10 ** digits;
  return String(binCode % mod).padStart(digits, '0');
}

export function generateTotpSecret(bytes = 20): string {
  return encodeBase32(randomBytes(bytes));
}

export function generateTotpCode(secretBase32: string, options?: TotpOptions): string {
  const stepSeconds = options?.stepSeconds ?? 30;
  const digits = options?.digits ?? 6;
  const timestampMs = options?.timestampMs ?? Date.now();
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  const secret = decodeBase32(secretBase32);
  return hotp(secret, counter, digits);
}

export function verifyTotpCode(secretBase32: string, code: string, options?: TotpOptions & { window?: number }): boolean {
  const stepSeconds = options?.stepSeconds ?? 30;
  const digits = options?.digits ?? 6;
  const timestampMs = options?.timestampMs ?? Date.now();
  const window = options?.window ?? 1;
  const normalizedCode = String(code || '').trim().replace(/\s+/g, '');
  if (!/^\d+$/.test(normalizedCode)) return false;

  const baseCounter = Math.floor(timestampMs / 1000 / stepSeconds);
  const secret = decodeBase32(secretBase32);
  for (let delta = -window; delta <= window; delta += 1) {
    const candidate = hotp(secret, baseCounter + delta, digits);
    if (candidate === normalizedCode) {
      return true;
    }
  }

  return false;
}

export function buildOtpAuthUri(params: { issuer: string; accountName: string; secret: string }): string {
  const issuer = params.issuer || 'CampusCast';
  const accountName = params.accountName || 'user';
  const secret = normalizeBase32(params.secret);
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const query = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });

  return `otpauth://totp/${label}?${query.toString()}`;
}
