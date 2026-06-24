# Interface: IEntityStorageVaultConnectorConstructorOptions

Options for the entity storage vault connector constructor.

## Properties

### vaultKeyEntityStorageType? {#vaultkeyentitystoragetype}

> `optional` **vaultKeyEntityStorageType?**: `string`

The vault key entity storage connector type.

#### Default

```ts
vault-key
```

***

### vaultSecretEntityStorageType? {#vaultsecretentitystoragetype}

> `optional` **vaultSecretEntityStorageType?**: `string`

The vault secret entity storage connector type.

#### Default

```ts
vault-secret
```

***

### config? {#config}

> `optional` **config?**: [`IEntityStorageVaultConnectorConfig`](IEntityStorageVaultConnectorConfig.md)

The entity storage vault connector configuration.
