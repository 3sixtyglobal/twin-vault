# Vault Models Examples

These examples show how to register vault connectors, use helper utilities for JWT workflows, and work with the shared key and encryption types.

## VaultConnectorHelper

```typescript
import { Jwt, type IJwtHeader, type IJwtPayload } from '@twin.org/web';
import {
  VaultConnectorFactory,
  VaultConnectorHelper,
  VaultEncryptionType,
  VaultKeyType,
  type IVaultConnector
} from '@twin.org/vault-models';

class InMemoryVaultConnector implements IVaultConnector {
  public className(): string {
    return 'InMemoryVaultConnector';
  }

  public async createKey(name: string, type: VaultKeyType): Promise<Uint8Array> {
    return Promise.resolve(new Uint8Array([type, name.length]));
  }

  public async addKey(
    _name: string,
    _type: VaultKeyType,
    _privateKey: Uint8Array,
    _publicKey?: Uint8Array
  ): Promise<void> {
    return Promise.resolve();
  }

  public async getKey(_name: string): Promise<{
    type: VaultKeyType;
    privateKey: Uint8Array;
    publicKey?: Uint8Array;
  }> {
    return Promise.resolve({
      type: VaultKeyType.Ed25519,
      privateKey: new Uint8Array([1, 2, 3]),
      publicKey: new Uint8Array([4, 5, 6])
    });
  }

  public async getKeyType(_name: string): Promise<VaultKeyType> {
    return Promise.resolve(VaultKeyType.Ed25519);
  }

  public async renameKey(_name: string, _newName: string): Promise<void> {
    return Promise.resolve();
  }

  public async removeKey(_name: string): Promise<void> {
    return Promise.resolve();
  }

  public async sign(_name: string, data: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(data);
  }

  public async verify(_name: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return Promise.resolve(data.length === signature.length);
  }

  public async encrypt(
    _name: string,
    _encryptionType: VaultEncryptionType,
    data: Uint8Array
  ): Promise<Uint8Array> {
    return Promise.resolve(data);
  }

  public async decrypt(
    _name: string,
    _encryptionType: VaultEncryptionType,
    encryptedData: Uint8Array
  ): Promise<Uint8Array> {
    return Promise.resolve(encryptedData);
  }

  public async setSecret<T>(_name: string, _data: T): Promise<void> {
    return Promise.resolve();
  }

  public async getSecret<T>(_name: string): Promise<T> {
    throw new Error('Not implemented in this example');
  }

  public async removeSecret(_name: string): Promise<void> {
    return Promise.resolve();
  }
}

VaultConnectorFactory.register('in-memory', () => new InMemoryVaultConnector());

const connector = VaultConnectorFactory.get('in-memory');

const header: IJwtHeader = {
  alg: 'EdDSA',
  typ: 'JWT'
};

const payload: IJwtPayload = {
  iss: 'example-service',
  sub: 'user-123',
  exp: Math.floor(Date.now() / 1000) + 600
};

const token = await VaultConnectorHelper.jwtSigner(connector, 'jwt-key', header, payload);
console.log(token.length > 0); // true

const decoded = Jwt.decode(token);
console.log(decoded.payload.sub); // user-123

const verified = await VaultConnectorHelper.jwtVerifier<IJwtHeader, IJwtPayload>(
  connector,
  'jwt-key',
  token
);

console.log(verified.payload.iss); // example-service
```

## Types And Constants

```typescript
import { VaultEncryptionType, VaultKeyType } from '@twin.org/vault-models';

const keyTypes: VaultKeyType[] = [
  VaultKeyType.Ed25519,
  VaultKeyType.Secp256k1,
  VaultKeyType.ChaCha20Poly1305
];

const encryptionType: VaultEncryptionType = VaultEncryptionType.ChaCha20Poly1305;

console.log(keyTypes.includes(VaultKeyType.Ed25519)); // true
console.log(encryptionType === VaultEncryptionType.ChaCha20Poly1305); // true
```
