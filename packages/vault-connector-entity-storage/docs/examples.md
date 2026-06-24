# Vault Connector Entity Storage Examples

These examples show common vault operations backed by entity storage, including key management, signing, encryption, and secret handling.

## EntityStorageVaultConnector

```typescript
import { Converter } from '@twin.org/core';
import { EntityStorageVaultConnector } from '@twin.org/vault-connector-entity-storage';
import { VaultEncryptionType, VaultKeyType } from '@twin.org/vault-models';

const connector = new EntityStorageVaultConnector({
  config: { prefix: 'app' }
});

const createdPublicKey = await connector.createKey('signing', VaultKeyType.Ed25519);
console.log(createdPublicKey.length); // 32

await connector.addKey(
  'encryption',
  VaultKeyType.ChaCha20Poly1305,
  Converter.hexToBytes('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')
);

const keyMaterial = await connector.getKey('signing');
console.log(keyMaterial.type === VaultKeyType.Ed25519); // true

const keyType = await connector.getKeyType('encryption');
console.log(keyType === VaultKeyType.ChaCha20Poly1305); // true
```

```typescript
import { Converter } from '@twin.org/core';
import { EntityStorageVaultConnector } from '@twin.org/vault-connector-entity-storage';
import { VaultKeyType } from '@twin.org/vault-models';

const connector = new EntityStorageVaultConnector({
  config: { prefix: 'tenant-a' }
});

await connector.createKey('old-signing', VaultKeyType.Ed25519);
await connector.renameKey('old-signing', 'current-signing');

const payload = Converter.utf8ToBytes('request-body');
const signature = await connector.sign('current-signing', payload);
const verified = await connector.verify('current-signing', payload, signature);

console.log(verified); // true

await connector.removeKey('current-signing');
```

```typescript
import { Converter } from '@twin.org/core';
import { EntityStorageVaultConnector } from '@twin.org/vault-connector-entity-storage';
import { VaultEncryptionType, VaultKeyType } from '@twin.org/vault-models';

const connector = new EntityStorageVaultConnector();

await connector.createKey('cipher', VaultKeyType.ChaCha20Poly1305);

const plaintext = Converter.utf8ToBytes('sensitive-value');
const encrypted = await connector.encrypt(
  'cipher',
  VaultEncryptionType.ChaCha20Poly1305,
  plaintext
);
const decrypted = await connector.decrypt(
  'cipher',
  VaultEncryptionType.ChaCha20Poly1305,
  encrypted
);

console.log(Converter.bytesToUtf8(decrypted)); // sensitive-value
```

```typescript
import { EntityStorageVaultConnector } from '@twin.org/vault-connector-entity-storage';

interface IUserSecret {
  apiKey: string;
  region: string;
}

const connector = new EntityStorageVaultConnector();

await connector.setSecret<IUserSecret>('service-config', {
  apiKey: 'live_123456',
  region: 'eu-west-1'
});

const secret = await connector.getSecret<IUserSecret>('service-config');
console.log(secret.region); // eu-west-1

await connector.removeSecret('service-config');
```

```typescript
import { EntityStorageVaultConnector } from '@twin.org/vault-connector-entity-storage';

const connector = new EntityStorageVaultConnector();
console.log(connector.className()); // EntityStorageVaultConnector
```

## VaultKey

```typescript
import type { VaultKey } from '@twin.org/vault-connector-entity-storage';
import { VaultKeyType } from '@twin.org/vault-models';

const vaultKey: VaultKey = {
  id: 'app-signing',
  type: VaultKeyType.Ed25519,
  privateKey: 'WmFuN0RvY3VtZW50ZWRFeGFtcGxlS2V5',
  publicKey: 'TXlQdWJsaWNLZXlGb3JFeGFtcGxl'
};

console.log(vaultKey.id); // app-signing
```

## VaultSecret

```typescript
import type { VaultSecret } from '@twin.org/vault-connector-entity-storage';

const vaultSecret: VaultSecret = {
  id: 'app-db-credentials',
  data: {
    username: 'service-user',
    password: 'strong-password'
  }
};

console.log(vaultSecret.id); // app-db-credentials
```

## Functions

```typescript
import { initSchema } from '@twin.org/vault-connector-entity-storage';

initSchema();
```
