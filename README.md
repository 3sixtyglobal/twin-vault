# 3Sixty Vault

This repository provides a focused set of vault components that help teams implement key management, encryption, signing, and secret handling with a consistent integration approach across services. The packages are designed to reduce repeated implementation work by combining shared contracts with connector specific behaviour in a way that remains predictable for both local development and production operations.

Together, these components support a clean boundary between application logic and vault infrastructure, making it easier to adopt secure workflows, swap connector implementations when needed, and maintain reliable behaviour across environments as systems evolve.

## Packages

- [vault-models](packages/vault-models/README.md) - Shared models and factory utilities for consistent vault connector integration
- [vault-connector-entity-storage](packages/vault-connector-entity-storage/README.md) - Entity storage backed connector for persisted vault key and secret workflows
- [vault-connector-hashicorp](packages/vault-connector-hashicorp/README.md) - HashiCorp Vault connector for transit cryptography and KV secret workflows

## Contributing

To contribute to this package see the guidelines for building and publishing in [CONTRIBUTING](./CONTRIBUTING.md)

## Origin

This repository is derived from the original [iotaledger/twin-vault](https://github.com/iotaledger/twin-vault) repository.
