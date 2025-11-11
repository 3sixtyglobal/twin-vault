// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import path from "node:path";
import { Guards } from "@twin.org/core";
import * as dotenv from "dotenv";
import { HashicorpVaultConnector } from "../src/hashicorpVaultConnector.js";
import type { IHashicorpVaultConnectorConfig } from "../src/models/IHashicorpVaultConnectorConfig.js";

dotenv.config({
	path: [path.join(__dirname, ".env"), path.join(__dirname, ".env.dev")],
	quiet: true
});

console.debug("Setting up test environment from .env and .env.dev files");

Guards.stringValue("TestEnv", "VAULT_ADDRESS", process.env.VAULT_ADDRESS);
Guards.stringValue("TestEnv", "VAULT_TOKEN", process.env.VAULT_TOKEN);
Guards.stringValue("TestEnv", "VAULT_KV_MOUNT_PATH", process.env.VAULT_KV_MOUNT_PATH);
Guards.stringValue("TestEnv", "VAULT_TRANSIT_MOUNT_PATH", process.env.VAULT_TRANSIT_MOUNT_PATH);
Guards.stringValue("TestEnv", "VAULT_API_VERSION", process.env.VAULT_API_VERSION);

export const TEST_VAULT_CONFIG: IHashicorpVaultConnectorConfig = {
	endpoint: process.env.VAULT_ADDRESS ?? "http://localhost:8200",
	token: process.env.VAULT_TOKEN ?? "root",
	kvMountPath: process.env.VAULT_KV_MOUNT_PATH ?? "secret",
	transitMountPath: process.env.VAULT_TRANSIT_MOUNT_PATH ?? "transit",
	apiVersion: process.env.VAULT_API_VERSION ?? "v1"
};

/**
 * Cleans up the secrets from the vault.
 * @param secretNames - The names of the secrets to clean up.
 */
export async function cleanupSecrets(secretNames: string[]): Promise<void> {
	const vaultConnector = new HashicorpVaultConnector({
		config: TEST_VAULT_CONFIG
	});
	await vaultConnector.bootstrap();

	for (const secretName of secretNames) {
		try {
			await vaultConnector.removeSecret(secretName);
		} catch {}
	}
}

/**
 * Cleans up the keys from the vault.
 * @param keyNames - The names of the keys to clean up.
 */
export async function cleanupKeys(keyNames: string[]): Promise<void> {
	const vaultConnector = new HashicorpVaultConnector({
		config: TEST_VAULT_CONFIG
	});
	await vaultConnector.bootstrap();

	for (const keyName of keyNames) {
		try {
			await vaultConnector.removeKey(keyName);
		} catch {}
	}
}
