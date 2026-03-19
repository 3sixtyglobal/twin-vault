# Interface: IHashicorpVaultConnectorConfig

Configuration for the Hashicorp Vault Connector.

## Properties

### endpoint {#endpoint}

> **endpoint**: `string`

The address of the Hashicorp Vault (e.g., "http://localhost:8200").

***

### token {#token}

> **token**: `string`

The authentication token for the Hashicorp Vault.

***

### kvMountPath? {#kvmountpath}

> `optional` **kvMountPath?**: `string`

The mount path for the KV Secrets Engine (e.g., "secret)

***

### transitMountPath? {#transitmountpath}

> `optional` **transitMountPath?**: `string`

The mount path for the Transit Secrets Engine (e.g., "transit").

***

### apiVersion? {#apiversion}

> `optional` **apiVersion?**: `string`

The version of the Hashicorp Vault API (e.g., "v1").

***

### timeout? {#timeout}

> `optional` **timeout?**: `number`

The request timeout in milliseconds.

***

### namespace? {#namespace}

> `optional` **namespace?**: `string`

The namespace for the Hashicorp Vault if using Vault Enterprise.

***

### prefix? {#prefix}

> `optional` **prefix?**: `string`

A prefix for the keys stored in the Hashicorp Vault.
