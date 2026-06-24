# Vault Packages

## vault-models

The package serves as a foundational component within the repository. Its primary purpose is to provide shared models and factory utilities for vault integrations, so other components can rely on consistent contracts for key and secret workflows. By doing so, it enables other packages to build upon a consistent and reliable base. This package is integral to ensuring that common functionality is centralised and reusable across the ecosystem.

- [README](../packages/vault-models/README.md)
- [Examples](../packages/vault-models/docs/examples.md)
- [Changelog](../packages/vault-models/docs/changelog.md)

## vault-connector-entity-storage

This package is designed to handle persisted key and secret operations through an entity storage backend using a common connector interface. It plays a crucial role in ensuring that inputs and outputs across the repository conform to expected standards, thereby reducing integration errors and improving maintainability. Its implementation reflects a focus on semantic clarity and interoperability.

- [README](../packages/vault-connector-entity-storage/README.md)
- [Examples](../packages/vault-connector-entity-storage/docs/examples.md)
- [Changelog](../packages/vault-connector-entity-storage/docs/changelog.md)

## vault-connector-hashicorp

This package focuses on integration with [HashiCorp Vault](https://developer.hashicorp.com/vault) for transit cryptography and KV secret workflows. Its role is to ensure that services can use managed vault capabilities consistently across different environments. The package embodies best practices for external service integration and reproducible operational behaviour.

- [README](../packages/vault-connector-hashicorp/README.md)
- [Examples](../packages/vault-connector-hashicorp/docs/examples.md)
- [Changelog](../packages/vault-connector-hashicorp/docs/changelog.md)
