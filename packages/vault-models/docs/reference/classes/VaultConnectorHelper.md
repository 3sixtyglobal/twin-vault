# Class: VaultConnectorHelper

Helpers for vault connectors.

## Constructors

### Constructor

> **new VaultConnectorHelper**(): `VaultConnectorHelper`

#### Returns

`VaultConnectorHelper`

## Properties

### CLASS\_NAME {#class_name}

> `readonly` `static` **CLASS\_NAME**: `string`

Runtime name for the class.

## Methods

### jwtSigner() {#jwtsigner}

> `static` **jwtSigner**(`vaultConnector`, `keyName`, `header`, `payload`): `Promise`\<`string`\>

Sign a JWT using vault connector.

#### Parameters

##### vaultConnector

[`IVaultConnector`](../interfaces/IVaultConnector.md)

The vault connector to use.

##### keyName

`string`

The name of the key to sign with.

##### header

`JWTHeaderParameters`

The header to sign.

##### payload

`JWTPayload`

The payload to sign.

#### Returns

`Promise`\<`string`\>

The token.

***

### jwtVerifier() {#jwtverifier}

> `static` **jwtVerifier**\<`T`, `U`\>(`vaultConnector`, `keyName`, `token`): `Promise`\<\{ `header`: `T`; `payload`: `U`; \}\>

Verify a JWT using a vault connector.

#### Type Parameters

##### T

`T` *extends* `JWTHeaderParameters`

##### U

`U` *extends* `JWTPayload`

#### Parameters

##### vaultConnector

[`IVaultConnector`](../interfaces/IVaultConnector.md)

The vault connector to use.

##### keyName

`string`

The name of the key to verify with.

##### token

`string`

The token to verify.

#### Returns

`Promise`\<\{ `header`: `T`; `payload`: `U`; \}\>

The header and payload if verification successful.

***

### buildKeyName() {#buildkeyname}

> `static` **buildKeyName**(...`keyParts`): `string`

Build a key name from parts.

#### Parameters

##### keyParts

...`string`[]

The parts of the key.

#### Returns

`string`

The constructed key name.
