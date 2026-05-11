# TWIN Vault Connector Hashicorp

This package integrates managed key and secret operations with HashiCorp Vault, providing connector APIs for transit cryptography and KV secret workflows in externally hosted vault environments.

## Installation

```shell
npm install @twin.org/vault-connector-hashicorp
```

## Docker

To perform testing of this component it may be necessary to launch a local instance to communicate with.

```shell
docker run -d --name twin-vault-hashicorp --cap-add=IPC_LOCK -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:1.21.4
```

## Examples

Usage of the APIs is shown in the examples [docs/examples.md](docs/examples.md)

## Reference

Detailed reference documentation for the API can be found in [docs/reference/index.md](docs/reference/index.md)

## Changelog

The changes between each version can be found in [docs/changelog.md](docs/changelog.md)
