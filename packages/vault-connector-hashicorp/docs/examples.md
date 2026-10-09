# Vault Connector Hashicorp Examples

These examples show how to connect to a Vault instance, inspect connector health, manage keys, sign and encrypt payloads, and work with secret versions.

## HashicorpVaultConnector

```typescript
import { HealthStatus } from '@3sixty/core';
import { HashicorpVaultConnector } from '@3sixty/vault-connector-hashicorp';

const connector = new HashicorpVaultConnector({
  config: {
    endpoint: 'http://127.0.0.1:8200',
    token: 'root-token',
    kvMountPath: 'secret',
    transitMountPath: 'transit',
    prefix: 'tenant-a'
  }
});

const ready = await connector.bootstrap();
console.log(ready); // true

const health = await connector.health();
console.log(health[0].status === HealthStatus.Ok); // true

console.log(connector.className()); // HashicorpVaultConnector
```

```typescript
import { HashicorpVaultConnector } from '@3sixty/vault-connector-hashicorp';

interface IApiSecret {
  clientId: string;
  clientSecret: string;
}

const connector = new HashicorpVaultConnector({
  config: { endpoint: 'http://127.0.0.1:8200', token: 'root-token' }
});

await connector.setSecret<IApiSecret>('payments', {
  clientId: 'svc-payments',
  clientSecret: 'secret-value'
});

const secret = await connector.getSecret<IApiSecret>('payments');
console.log(secret.clientId); // svc-payments

const versions = await connector.getSecretVersions('payments');
console.log(versions.length > 0); // true

await connector.removeSecret('payments');
```

```typescript
import { Converter } from '@3sixty/core';
import { HashicorpVaultConnector } from '@3sixty/vault-connector-hashicorp';
import { VaultKeyType } from '@3sixty/vault-models';

const connector = new HashicorpVaultConnector({
  config: { endpoint: 'http://127.0.0.1:8200', token: 'root-token' }
});

const publicKey = await connector.createKey('jwt-signing', VaultKeyType.Ed25519);
console.log(publicKey.length); // 32

const privateKey = Converter.hexToBytes(
  '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
);
const addedPublicKey = Converter.hexToBytes(
  '11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff'
);

await connector.addKey('imported-signing', VaultKeyType.Ed25519, privateKey, addedPublicKey);

const key = await connector.getKey('jwt-signing');
console.log(key.type === VaultKeyType.Ed25519); // true

const keyType = await connector.getKeyType('jwt-signing');
console.log(keyType === VaultKeyType.Ed25519); // true
```

```typescript
import { HashicorpVaultConnector } from '@3sixty/vault-connector-hashicorp';
import { VaultKeyType } from '@3sixty/vault-models';

const connector = new HashicorpVaultConnector({
  config: { endpoint: 'http://127.0.0.1:8200', token: 'root-token' }
});

await connector.createKey('old-key-name', VaultKeyType.Ed25519);
await connector.renameKey('old-key-name', 'current-key-name');

const deletionAllowedBefore = await connector.getKeyDeleteConfiguration('current-key-name');
console.log(deletionAllowedBefore); // false

await connector.updateKeyConfig('current-key-name', true, true);

const deletionAllowedAfter = await connector.getKeyDeleteConfiguration('current-key-name');
console.log(deletionAllowedAfter); // true

await connector.removeKey('current-key-name');
```

Payloads are encrypted locally under a per-call data key that is wrapped by the transit key, so only the data key travels through Vault and the payload size is not bounded by the Vault request limits.

```typescript
import { Converter } from '@3sixty/core';
import { HashicorpVaultConnector } from '@3sixty/vault-connector-hashicorp';
import { VaultEncryptionType, VaultKeyType } from '@3sixty/vault-models';

const connector = new HashicorpVaultConnector({
  config: { endpoint: 'http://127.0.0.1:8200', token: 'root-token' }
});

await connector.createKey('signing-key', VaultKeyType.Ed25519);
await connector.createKey('crypto-key', VaultKeyType.ChaCha20Poly1305);

const bytes = Converter.utf8ToBytes('signed payload');
const signature = await connector.sign('signing-key', bytes);
const verified = await connector.verify('signing-key', bytes, signature);

console.log(verified); // true

const encrypted = await connector.encrypt(
  'crypto-key',
  VaultEncryptionType.ChaCha20Poly1305,
  bytes
);
const decrypted = await connector.decrypt(
  'crypto-key',
  VaultEncryptionType.ChaCha20Poly1305,
  encrypted
);

console.log(Converter.bytesToUtf8(decrypted)); // signed payload
```

```typescript
import { HashicorpVaultConnector } from '@3sixty/vault-connector-hashicorp';
import { VaultKeyType } from '@3sixty/vault-models';

const connector = new HashicorpVaultConnector({
  config: { endpoint: 'http://127.0.0.1:8200', token: 'root-token' }
});

await connector.createKey('backup-demo', VaultKeyType.Ed25519);

const backup = await connector.backupKey('backup-demo');
await connector.restoreKey('backup-demo-restored', backup);

const exportedPublic = await connector.exportKey('backup-demo-restored', 'public-key');
console.log(exportedPublic.name); // backup-demo-restored

await connector.importKey(
  'pem-import',
  'ed25519',
  '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDf...\n-----END PRIVATE KEY-----'
);
```
