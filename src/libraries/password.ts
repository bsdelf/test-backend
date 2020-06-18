import crypto from 'crypto';

const randomBits = (n: number) => crypto.randomBytes(n / 8);

const kdfV1 = (
  password: crypto.BinaryLike,
  salt: crypto.BinaryLike,
  bits: number
): Promise<Buffer> => {
  const options = {
    N: 16384,
    r: 8,
    p: 1,
  };
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, bits / 8, options, (err: Error | null, derivedKey: Buffer) => {
      if (err) {
        reject(err);
      } else {
        resolve(derivedKey);
      }
    });
  });
};

export interface HashedPassword {
  v: number;
  salt: string;
  hash: string;
}

export interface EncryptedData {
  v: number;
  salt: string;
  iv: string;
  tag: string;
  data: string;
}

class InvalidPasswordVersion extends Error {
  constructor(v: number) {
    super(`Invalid password version, expected: ${v}`);
  }
}

export class Password {
  constructor(private password: string) {}

  async hash(): Promise<HashedPassword> {
    // sha
    const sha256 = crypto.createHash('sha256');
    sha256.update(this.password);
    const digest = sha256.digest();
    // kdf
    const salt = randomBits(128);
    const hash = await kdfV1(digest, salt, 256);
    return { v: 1, salt: salt.toString('hex'), hash: hash.toString('hex') };
  }

  async verify(input: HashedPassword): Promise<boolean> {
    if (input.v !== 1) {
      throw new InvalidPasswordVersion(1);
    }
    // sha
    const sha256 = crypto.createHash('sha256');
    sha256.update(this.password);
    const digest = sha256.digest();
    // kdf
    const salt = Buffer.from(input.salt, 'hex');
    const expectedHash = Buffer.from(input.hash, 'hex');
    const actualHash = await kdfV1(digest, salt, 256);
    return actualHash.equals(expectedHash);
  }

  async encrypt(data: Buffer): Promise<EncryptedData> {
    // kdf
    const salt = randomBits(128);
    const key = await kdfV1(this.password, salt, 256);
    // aes
    const iv = randomBits(256);
    const aes = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([aes.update(data), aes.final()]);
    const tag = aes.getAuthTag();
    return {
      v: 1,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      data: encrypted.toString('hex'),
    };
  }

  async decrypt(input: EncryptedData): Promise<Buffer> {
    if (input.v !== 1) {
      throw new InvalidPasswordVersion(1);
    }
    // kdf
    const salt = Buffer.from(input.salt, 'hex');
    const key = await kdfV1(this.password, salt, 256);
    // aes
    const iv = Buffer.from(input.iv, 'hex');
    const tag = Buffer.from(input.tag, 'hex');
    const encrypted = Buffer.from(input.data, 'hex');
    const aes = crypto.createDecipheriv('aes-256-gcm', key, iv).setAuthTag(tag);
    return Buffer.concat([aes.update(encrypted), aes.final()]);
  }
}
