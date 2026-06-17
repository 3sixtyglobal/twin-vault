# Interface: IVaultConnector

Interface describing a vault securely storing data.

## Extends

- `IComponent`

## Methods

### createKey() {#createkey}

> **createKey**(`name`, `type`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Generate a new key and store it in the vault.

#### Parameters

##### name

`string`

The name of the key to generate and store in the vault.

##### type

[`VaultKeyType`](../type-aliases/VaultKeyType.md)

The type of key to create.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

The public key for the key pair.

***

### addKey() {#addkey}

> **addKey**(`name`, `type`, `privateKey`, `publicKey?`): `Promise`\<`void`\>

Add an existing key to the vault.

#### Parameters

##### name

`string`

The name of the key to add to the vault.

##### type

[`VaultKeyType`](../type-aliases/VaultKeyType.md)

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

***

### getKey() {#getkey}

> **getKey**(`name`, `components?`): `Promise`\<\{ `type`: [`VaultKeyType`](../type-aliases/VaultKeyType.md); `privateKey?`: `Uint8Array`\<`ArrayBufferLike`\>; `publicKey?`: `Uint8Array`\<`ArrayBufferLike`\>; \}\>

Get a key from the vault.

#### Parameters

##### name

`string`

The name of the key to get from the vault.

##### components?

`"public"` \| `"private"` \| `"both"`

Which key components to return, defaults to "both".

#### Returns

`Promise`\<\{ `type`: [`VaultKeyType`](../type-aliases/VaultKeyType.md); `privateKey?`: `Uint8Array`\<`ArrayBufferLike`\>; `publicKey?`: `Uint8Array`\<`ArrayBufferLike`\>; \}\>

The key, publicKey can be undefined if key is symmetric, privateKey can be undefined if only public was requested.

#### Throws

GeneralError if "private" is requested for a symmetric key.

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

***

### getKeyType() {#getkeytype}

> **getKeyType**(`name`): `Promise`\<[`VaultKeyType`](../type-aliases/VaultKeyType.md)\>

Get the type of a key from the vault without retrieving the key material.

#### Parameters

##### name

`string`

The name of the key.

#### Returns

`Promise`\<[`VaultKeyType`](../type-aliases/VaultKeyType.md)\>

The key type.

#### Throws

NotFoundError if the key does not exist.

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

The name of the secret in the vault to set.

##### data

`T`

The secret to add to the vault.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the secret has been stored.

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

The name of the secret in the vault to get.

#### Returns

`Promise`\<`T`\>

The secret from the vault.

#### Throws

Error if the secret is not found.

***

### removeSecret() {#removesecret}

> **removeSecret**(`name`): `Promise`\<`void`\>

Remove a secret from the vault.

#### Parameters

##### name

`string`

The name of the secret in the vault to remove.

#### Returns

`Promise`\<`void`\>

A promise that resolves when the secret has been removed.

#### Throws

Error if the secret is not found.
