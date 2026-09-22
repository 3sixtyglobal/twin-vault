# Class: HashicorpVaultConnector

Class for performing vault operations using HashiCorp Vault.

## Implements

- `IVaultConnector`
- `IHealthProviderComponent`

## Constructors

### Constructor

> **new HashicorpVaultConnector**(`options`): `HashicorpVaultConnector`

Create a new instance of HashicorpVaultConnector.

#### Parameters

##### options

[`IHashicorpVaultConnectorConstructorOptions`](../interfaces/IHashicorpVaultConnectorConstructorOptions.md)

The options for the vault connector.

#### Returns

`HashicorpVaultConnector`

## Properties

### CLASS\_NAME {#class_name}

> `readonly` `static` **CLASS\_NAME**: `string`

Runtime name for the class.

***

### NAMESPACE {#namespace}

> `readonly` `static` **NAMESPACE**: `string` = `"hashicorp"`

The namespace supported by the vault connector.

## Methods

### className() {#classname}

> **className**(): `string`

Returns the class name of the component.

#### Returns

`string`

The class name of the component.

#### Implementation of

`IVaultConnector.className`

***

### health() {#health}

> **health**(): `Promise`\<`IHealth`[]\>

Returns the health status of the component.

#### Returns

`Promise`\<`IHealth`[]\>

The health status of the component.

#### Implementation of

`IHealthProviderComponent.health`

***

### bootstrap() {#bootstrap}

> **bootstrap**(`nodeLoggingComponentType?`): `Promise`\<`boolean`\>

Bootstrap the vault connector and ensure connectivity.

#### Parameters

##### nodeLoggingComponentType?

`string`

The node logging component type.

#### Returns

`Promise`\<`boolean`\>

True if the bootstrapping process was successful.

#### Implementation of

`IVaultConnector.bootstrap`

***

### setSecret() {#setsecret}

> **setSecret**\<`T`\>(`name`, `data`): `Promise`\<`void`\>

Store a secret in the vault.

#### Type Parameters

##### T

`T`

#### Parameters

##### name

`string`

The name of the item in the vault to set.

##### data

`T`

The item to add to the vault.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the secret has been stored.

#### Implementation of

`IVaultConnector.setSecret`

***

### stop() {#stop}

> **stop**(`nodeLoggingComponentType?`): `Promise`\<`void`\>

Stop the component and release the key metadata cache.

#### Parameters

##### nodeLoggingComponentType?

`string`

The node logging component type.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the component has stopped.

#### Implementation of

`IVaultConnector.stop`

***

### secretExists() {#secretexists}

> **secretExists**(`name`): `Promise`\<`boolean`\>

Check if a secret exists in the vault.

#### Parameters

##### name

`string`

The name of the secret to check.

#### Returns

`Promise`\<`boolean`\>

True if the secret exists, false otherwise.

#### Implementation of

`IVaultConnector.secretExists`

***

### getSecret() {#getsecret}

> **getSecret**\<`T`\>(`name`): `Promise`\<`T`\>

Get a secret from the vault.

#### Type Parameters

##### T

`T`

#### Parameters

##### name

`string`

The name of the item in the vault to get.

#### Returns

`Promise`\<`T`\>

The item from the vault.

#### Throws

Error if the item is not found.

#### Implementation of

`IVaultConnector.getSecret`

***

### removeSecret() {#removesecret}

> **removeSecret**(`name`): `Promise`\<`void`\>

Remove a secret from the vault.

#### Parameters

##### name

`string`

The name of the item in the vault to remove.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the secret has been removed.

#### Throws

Error if the item is not found.

#### Implementation of

`IVaultConnector.removeSecret`

***

### createKey() {#createkey}

> **createKey**(`name`, `type`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Generate a new key and store it in the vault.

#### Parameters

##### name

`string`

The name of the key to generate and store in the vault.

##### type

`VaultKeyType`

The type of key to create.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

The public key for the key pair.

#### Implementation of

`IVaultConnector.createKey`

***

### addKey() {#addkey}

> **addKey**(`name`, `type`, `privateKey`, `publicKey?`): `Promise`\<`void`\>

Add an existing key to the vault.

#### Parameters

##### name

`string`

The name of the key to add to the vault.

##### type

`VaultKeyType`

The type of key to add.

##### privateKey

`Uint8Array`

The private key.

##### publicKey?

`Uint8Array`\<`ArrayBufferLike`\>

The public key, can be undefined if the key type is symmetric.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the key has been stored.

#### Implementation of

`IVaultConnector.addKey`

***

### getKey() {#getkey}

> **getKey**(`name`, `components?`): `Promise`\<\{ `type`: `VaultKeyType`; `privateKey?`: `Uint8Array`\<`ArrayBufferLike`\>; `publicKey?`: `Uint8Array`\<`ArrayBufferLike`\>; \}\>

Get a key from the vault.

#### Parameters

##### name

`string`

The name of the key to get.

##### components?

`"public"` \| `"private"` \| `"both"`

Which key components to return, defaults to "both".

#### Returns

`Promise`\<\{ `type`: `VaultKeyType`; `privateKey?`: `Uint8Array`\<`ArrayBufferLike`\>; `publicKey?`: `Uint8Array`\<`ArrayBufferLike`\>; \}\>

The key, publicKey can be undefined if key is symmetric, privateKey can be undefined if only public was requested.

#### Throws

GeneralError if "private" is requested for a symmetric key.

#### Implementation of

`IVaultConnector.getKey`

***

### keyExists() {#keyexists}

> **keyExists**(`name`): `Promise`\<`boolean`\>

Check if a key exists in the vault.

#### Parameters

##### name

`string`

The name of the key to check.

#### Returns

`Promise`\<`boolean`\>

True if the key exists, false otherwise.

#### Implementation of

`IVaultConnector.keyExists`

***

### getKeyType() {#getkeytype}

> **getKeyType**(`name`): `Promise`\<`VaultKeyType`\>

Get the type of a key from the vault without retrieving the key material.

#### Parameters

##### name

`string`

The name of the key.

#### Returns

`Promise`\<`VaultKeyType`\>

The key type.

#### Throws

NotFoundError if the key does not exist.

#### Implementation of

`IVaultConnector.getKeyType`

***

### renameKey() {#renamekey}

> **renameKey**(`name`, `newName`): `Promise`\<`void`\>

Rename a key in the vault.

#### Parameters

##### name

`string`

The name of the key to rename.

##### newName

`string`

The new name of the key.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the key has been renamed.

#### Implementation of

`IVaultConnector.renameKey`

***

### removeKey() {#removekey}

> **removeKey**(`name`): `Promise`\<`void`\>

Remove a key from the vault.

#### Parameters

##### name

`string`

The name of the key to remove.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the key has been removed.

#### Implementation of

`IVaultConnector.removeKey`

***

### sign() {#sign}

> **sign**(`name`, `data`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Sign data.

#### Parameters

##### name

`string`

The name of the key to use.

##### data

`Uint8Array`

The data to sign.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

The signature.

#### Implementation of

`IVaultConnector.sign`

***

### verify() {#verify}

> **verify**(`name`, `data`, `signature`): `Promise`\<`boolean`\>

Verify a signature.

#### Parameters

##### name

`string`

The name of the key to use.

##### data

`Uint8Array`

The data to verify.

##### signature

`Uint8Array`

The signature to verify.

#### Returns

`Promise`\<`boolean`\>

True if the signature is valid.

#### Implementation of

`IVaultConnector.verify`

***

### encrypt() {#encrypt}

> **encrypt**(`name`, `encryptionType`, `data`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Encrypt data locally under a data key wrapped by the transit key.

#### Parameters

##### name

`string`

The name of the key to use.

##### encryptionType

`0`

The type of encryption to use.

##### data

`Uint8Array`

The data to encrypt.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

The encrypted data.

#### Implementation of

`IVaultConnector.encrypt`

***

### decrypt() {#decrypt}

> **decrypt**(`name`, `encryptionType`, `encryptedData`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Decrypt data, either an envelope or data encrypted directly by the transit key.

#### Parameters

##### name

`string`

The name of the key to use.

##### encryptionType

`0`

The type of encryption to use.

##### encryptedData

`Uint8Array`

The encrypted data to decrypt.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

The decrypted data.

#### Implementation of

`IVaultConnector.decrypt`

***

### getSecretVersions() {#getsecretversions}

> **getSecretVersions**(`name`): `Promise`\<`number`[]\>

Get the versions of a secret.

#### Parameters

##### name

`string`

The name of the secret.

#### Returns

`Promise`\<`number`[]\>

The versions of the secret.

#### Throws

Error if the secret is not found.

***

### updateKeyConfig() {#updatekeyconfig}

> **updateKeyConfig**(`name`, `deletionAllowed?`, `exportable?`): `Promise`\<`void`\>

Update the configuration of a key.

#### Parameters

##### name

`string`

The name of the key to update.

##### deletionAllowed?

`boolean`

Whether the key can be deleted.

##### exportable?

`boolean`

Whether the key can be exported.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the key configuration has been updated.

***

### backupKey() {#backupkey}

> **backupKey**(`name`): `Promise`\<`string`\>

Backup a key from the vault.

#### Parameters

##### name

`string`

The name of the key to backup.

#### Returns

`Promise`\<`string`\>

The Base64-encoded backup payload.

#### Throws

Error if the key cannot be exported or found.

***

### restoreKey() {#restorekey}

> **restoreKey**(`name`, `backup`): `Promise`\<`void`\>

Restore a key to the vault.

#### Parameters

##### name

`string`

The name of the key to restore.

##### backup

`string`

The Base64-encoded backup payload.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the key has been restored.

#### Throws

Error if the key cannot be restored.

***

### importKey() {#importkey}

> **importKey**(`name`, `type`, `privateKeyPem`): `Promise`\<`void`\>

Import a key to the vault.

#### Parameters

##### name

`string`

The name of the key to import.

##### type

`string`

The type of key to import, e.g. "ed25519".

##### privateKeyPem

`string`

The PEM bundle of the key to import.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the key has been imported.

#### Throws

Error if the key cannot be imported.

***

### exportKey() {#exportkey}

> **exportKey**(`name`, `keyPath`, `version?`): `Promise`\<\{ `type`: `VaultKeyType`; `key`: `Uint8Array`; `name`: `string`; \}\>

Export the key from the vault.

#### Parameters

##### name

`string`

The name of the key.

##### keyPath

`"signing-key"` \| `"encryption-key"` \| `"public-key"`

The path of the key. Defaults to "signing-key".

##### version?

`string`

The version of the key. If omitted, all versions of the key will be returned.

#### Returns

`Promise`\<\{ `type`: `VaultKeyType`; `key`: `Uint8Array`; `name`: `string`; \}\>

The key details.

#### Throws

Error if the key cannot be exported or found.

***

### getKeyDeleteConfiguration() {#getkeydeleteconfiguration}

> **getKeyDeleteConfiguration**(`name`): `Promise`\<`boolean`\>

Get the key configuration.

#### Parameters

##### name

`string`

The name of the key to get the configuration for.

#### Returns

`Promise`\<`boolean`\>

True if the key can be deleted.
