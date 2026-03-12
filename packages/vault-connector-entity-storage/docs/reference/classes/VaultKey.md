# Class: VaultKey

Class defining a vault key.

## Constructors

### Constructor

> **new VaultKey**(): `VaultKey`

#### Returns

`VaultKey`

## Properties

### id {#id}

> **id**: `string`

The id.

***

### type {#type}

> **type**: `VaultKeyType`

The type of the key e.g. Ed25519, Secp256k1.

***

### privateKey {#privatekey}

> **privateKey**: `string`

The private key in base64 format.

***

### publicKey? {#publickey}

> `optional` **publicKey**: `string`

The public key in base64 format.
