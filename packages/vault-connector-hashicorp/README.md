# TWIN Vault Connector Hashicorp

This package provides a reusable vault component for secure key and secret workflows across services.

## Installation

```shell
npm install @twin.org/vault-connector-hashicorp
```

## Testing

Docker launch configuration for integration test components.

```shell
docker run -d --name twin-vault-hashicorp --cap-add=IPC_LOCK -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:1.18.0
```

## Examples

Usage of the APIs is shown in the examples [docs/examples.md](docs/examples.md)

## Reference

Detailed reference documentation for the API can be found in [docs/reference/index.md](docs/reference/index.md)

## Changelog

The changes between each version can be found in [docs/changelog.md](docs/changelog.md)
