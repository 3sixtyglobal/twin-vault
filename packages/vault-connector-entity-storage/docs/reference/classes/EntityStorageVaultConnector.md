# Class: EntityStorageVaultConnector

Class for performing vault operations in entity storage.

## Implements

- `IVaultConnector`

## Constructors

### Constructor

> **new EntityStorageVaultConnector**(`options?`): `EntityStorageVaultConnector`

Create a new instance of EntityStorageVaultConnector.

#### Parameters

##### options?

[`IEntityStorageVaultConnectorConstructorOptions`](../interfaces/IEntityStorageVaultConnectorConstructorOptions.md)

The options for the connector.

#### Returns

`EntityStorageVaultConnector`

## Properties

### NAMESPACE {#namespace}

> `readonly` `static` **NAMESPACE**: `string` = `"entity-storage"`

The namespace supported by the vault connector.

***

### CLASS\_NAME {#class_name}

> `readonly` `static` **CLASS\_NAME**: `string`

Runtime name for the class.

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

The name of the key to get from the vault.

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

The name of the key to remove from the vault.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the key has been removed.

#### Implementation of

`IVaultConnector.removeKey`

***

### sign() {#sign}

> **sign**(`name`, `data`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Sign the data using a key in the vault.

#### Parameters

##### name

`string`

The name of the key to use for signing.

##### data

`Uint8Array`

The data to sign.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

The signature for the data.

#### Implementation of

`IVaultConnector.sign`

***

### verify() {#verify}

> **verify**(`name`, `data`, `signature`): `Promise`\<`boolean`\>

Verify the signature of the data using a key in the vault.

#### Parameters

##### name

`string`

The name of the key to use for verification.

##### data

`Uint8Array`

The data that was signed.

##### signature

`Uint8Array`

The signature to verify.

#### Returns

`Promise`\<`boolean`\>

True if the verification is successful.

#### Implementation of

`IVaultConnector.verify`

***

### encrypt() {#encrypt}

> **encrypt**(`name`, `encryptionType`, `data`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Encrypt the data using a key in the vault.

#### Parameters

##### name

`string`

The name of the key to use for encryption.

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

Decrypt the data using a key in the vault.

#### Parameters

##### name

`string`

The name of the key to use for decryption.

##### encryptionType

`0`

The type of encryption to use.

##### encryptedData

`Uint8Array`

The data to decrypt.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

The decrypted data.

#### Implementation of

`IVaultConnector.decrypt`

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
