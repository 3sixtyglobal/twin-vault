# TWIN Vault

This repository provides reusable building blocks for integrating secure key and secret workflows into applications and services. The packages are designed to standardise how vault operations are modelled, while allowing different connector implementations for local persistence and managed vault infrastructure.

Together, these packages support consistent key lifecycle handling, encryption and signing operations, and secret management patterns so teams can adopt a common vault abstraction across development and production environments.

## Packages

- [vault-models](packages/vault-models/README.md) - Shared models, types, and factory helpers for key management, encryption operations, and connector integration.
- [vault-connector-entity-storage](packages/vault-connector-entity-storage/README.md) - Entity storage connector for persisting vault keys and secrets with signing and encryption support.
- [vault-connector-hashicorp](packages/vault-connector-hashicorp/README.md) - HashiCorp Vault connector for transit and KV operations, including key lifecycle and secret management.

## Contributing

To contribute to this package see the guidelines for building and publishing in [CONTRIBUTING](./CONTRIBUTING.md)
