import crypto from 'node:crypto';

export function isScryptHash(value) {
  return typeof value === 'string' && value.startsWith('scrypt$');
}

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(password), salt, 64);
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}

export function verifyPassword(stored, password) {
  if (!stored) return false;

  // Compatibilidade: senhas antigas em texto puro
  if (!isScryptHash(stored)) {
    return String(stored) === String(password);
  }

  const parts = String(stored).split('$');
  if (parts.length !== 3) return false;

  const saltHex = parts[1];
  const keyHex = parts[2];

  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(keyHex, 'hex');
  const actual = crypto.scryptSync(String(password), salt, expected.length);
  return crypto.timingSafeEqual(expected, actual);
}
