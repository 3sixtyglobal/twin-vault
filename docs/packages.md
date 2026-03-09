# Vault Packages

## vault-models

This package serves as the shared contract layer for vault integrations. It defines common models and factory utilities that keep key management, encryption, and secret workflows consistent across connector implementations. By centralising these core abstractions, it provides a reliable base for interoperability throughout the repository.

- [README](../packages/vault-models/README.md)
- [Examples](../packages/vault-models/docs/examples.md)
- [Changelog](../packages/vault-models/docs/changelog.md)

## vault-connector-entity-storage

This package provides an entity storage backed connector for vault operations. It handles persisted key and secret workflows so applications can use signing, verification, encryption, and secret access with a consistent connector interface. Its design supports maintainable integration with storage centric service architectures.

- [README](../packages/vault-connector-entity-storage/README.md)
- [Examples](../packages/vault-connector-entity-storage/docs/examples.md)
- [Changelog](../packages/vault-connector-entity-storage/docs/changelog.md)

## vault-connector-hashicorp

This package integrates with [HashiCorp Vault](https://developer.hashicorp.com/vault) for transit cryptography and KV secret workflows. It focuses on external vault service integration for teams that need centralised operational controls, policy based access, and managed secret infrastructure.

- [README](../packages/vault-connector-hashicorp/README.md)
- [Examples](../packages/vault-connector-hashicorp/docs/examples.md)
- [Changelog](../packages/vault-connector-hashicorp/docs/changelog.md)
