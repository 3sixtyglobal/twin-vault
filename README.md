# TWIN Vault

This repository brings together modular vault components that help teams implement secure key and secret workflows with a consistent developer experience. The packages focus on a shared operational model for key lifecycle, encryption, signing, and secret handling so services can integrate vault capabilities without rebuilding the same foundations for each project.

By combining common models with connector implementations for different backends, the repository supports local development and managed infrastructure patterns while keeping integration behaviour predictable across environments.

## Packages

- [vault-models](packages/vault-models/README.md) - Shared vault models, contracts, and factory utilities for consistent connector integration.
- [vault-connector-entity-storage](packages/vault-connector-entity-storage/README.md) - Entity storage connector for persisting vault keys and secrets across application workflows.
- [vault-connector-hashicorp](packages/vault-connector-hashicorp/README.md) - [HashiCorp Vault](https://developer.hashicorp.com/vault) connector for transit cryptography and KV secret operations.

## Contributing

To contribute to this package see the guidelines for building and publishing in [CONTRIBUTING](./CONTRIBUTING.md)
