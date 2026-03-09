# Vault Packages

## vault-models

This package defines shared vault interfaces, factories, and type models for key management, encryption workflows, and connector interoperability. It provides a common contract layer that keeps vault integrations consistent across different connector implementations.

- [README](../packages/vault-models/README.md)
- [Examples](../packages/vault-models/docs/examples.md)
- [Changelog](../packages/vault-models/docs/changelog.md)

## vault-connector-entity-storage

This package provides a connector implementation that stores vault keys and secrets using entity storage abstractions. It enables applications to run signing, verification, encryption, and secret operations through a persistence-friendly backend.

- [README](../packages/vault-connector-entity-storage/README.md)
- [Examples](../packages/vault-connector-entity-storage/docs/examples.md)
- [Changelog](../packages/vault-connector-entity-storage/docs/changelog.md)

## vault-connector-hashicorp

This package integrates with [HashiCorp Vault](https://developer.hashicorp.com/vault) to provide key lifecycle management, transit cryptography, and secret storage operations. It is suited to deployments that need an external vault service with operational controls and policy-based access.

- [README](../packages/vault-connector-hashicorp/README.md)
- [Examples](../packages/vault-connector-hashicorp/docs/examples.md)
- [Changelog](../packages/vault-connector-hashicorp/docs/changelog.md)
