// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
// Tests for HashicorpVaultConnector-specific functionality not present in the shared
// IVaultConnector interface: health checks, exportKey, backupKey, restoreKey,
// updateKeyConfig, getKeyDeleteConfiguration, getSecretVersions.
import { Converter, HealthStatus } from "@twin.org/core";
import { Ed25519 } from "@twin.org/crypto";
import { VaultKeyType } from "@twin.org/vault-models";
import { cleanupKeys, cleanupSecrets, TEST_VAULT_CONFIG } from "./setupTestEnv.js";
import { HashicorpVaultConnector } from "../src/hashicorpVaultConnector.js";

const TEST_KEY_NAME = `test-hc-key=+/@!£$%^&*()${Converter.bytesToHex(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))}`;
const TEST_SECRET_NAME =
	"bootstrap-4d8819601e1955d4d2a1c98608629c58eb579692fb8c1b49b258726e31e8a8d4_mnemonic'";
const TEST_RESTORE_KEY_NAME =
	"did:iota:tst:0xac07260b1d822a6906018f3870aea8e50cf59fc46d29feffdf141997d25917c2/temp-vm-dkwsdrKHIM_7L1dBs-zWsA";
const TEST_RESTORE_NEW_KEY_NAME =
	"did:iota:tst:0xac07260b1d822a6906018f3870aea8e50cf59fc46d29feffdf141997d25917c2/immutable-proof";

let vaultConnector: HashicorpVaultConnector;

describe("HashicorpVaultConnector (extended)", () => {
	beforeEach(async () => {
		vaultConnector = new HashicorpVaultConnector({ config: TEST_VAULT_CONFIG });
		await vaultConnector.bootstrap();
		await cleanupKeys([TEST_KEY_NAME, TEST_RESTORE_KEY_NAME, TEST_RESTORE_NEW_KEY_NAME]);
		await cleanupSecrets([TEST_SECRET_NAME]);
	});

	test("can get health status when vault is available", async () => {
		const health = await vaultConnector.health();
		expect(Array.isArray(health)).toBe(true);
		expect(health.length).toBeGreaterThan(0);
		expect(health[0].source).toEqual("HashicorpVaultConnector");
		expect(health[0].status).toEqual(HealthStatus.Ok);
		expect(health[0].description).toEqual("healthDescription");
	});

	test("can fail to get health status with invalid config", async () => {
		const invalidConnector = new HashicorpVaultConnector({
			config: { endpoint: "http://invalid-vault:8200", token: "invalid-token", apiVersion: "v1" }
		});
		const health = await invalidConnector.health();
		expect(health[0].source).toEqual("HashicorpVaultConnector");
		expect(health[0].status).toEqual(HealthStatus.Error);
		expect(health[0].description).toEqual("healthDescription");
		expect(health[0].message).toEqual("vaultHealthCheckFailed");
	});

	test("can create and get asymmetric key ed25519 via exportKey", async () => {
		const publicKey = await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		expect(publicKey.length).toBeGreaterThan(0);

		const retrievedPublicKey = await vaultConnector.exportKey(TEST_KEY_NAME, "public-key");
		expect(retrievedPublicKey.key).toEqual(publicKey);

		const retrievedPrivateKey = await vaultConnector.exportKey(TEST_KEY_NAME, "signing-key");
		expect(retrievedPrivateKey.key).toBeDefined();

		const signature = Ed25519.sign(retrievedPrivateKey.key, Converter.utf8ToBytes("test-data"));
		expect(
			Ed25519.verify(retrievedPublicKey.key, Converter.utf8ToBytes("test-data"), signature)
		).toBe(true);
	});

	test("can create and get symmetric key chacha20poly1305 via exportKey", async () => {
		const publicKey = await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
		expect(publicKey.length).toBeGreaterThan(0);

		const retrieved = await vaultConnector.exportKey(TEST_KEY_NAME, "encryption-key");
		expect(retrieved.key).toEqual(publicKey);
	});

	test("can get key type without calling exportKey", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const exportKeySpy = vi.spyOn(vaultConnector, "exportKey");
		await vaultConnector.getKeyType(TEST_KEY_NAME);
		expect(exportKeySpy).not.toHaveBeenCalled();
	});

	test("can update key configuration to allow deletion", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		await vaultConnector.updateKeyConfig(TEST_KEY_NAME, true);
		const deleteConfiguration = await vaultConnector.getKeyDeleteConfiguration(TEST_KEY_NAME);
		expect(deleteConfiguration).toEqual(true);
	});

	test("can backup a key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const backup = await vaultConnector.backupKey(TEST_KEY_NAME);
		expect(typeof backup).toBe("string");
		expect(backup.length).toBeGreaterThan(0);
	});

	test("can restore a key", async () => {
		await vaultConnector.createKey(TEST_RESTORE_KEY_NAME, VaultKeyType.Ed25519);
		const backup = await vaultConnector.backupKey(TEST_RESTORE_KEY_NAME);
		await vaultConnector.restoreKey(TEST_RESTORE_NEW_KEY_NAME, backup);
		const original = await vaultConnector.exportKey(TEST_RESTORE_KEY_NAME, "public-key");
		const restored = await vaultConnector.exportKey(TEST_RESTORE_NEW_KEY_NAME, "public-key");
		expect(original.key).toEqual(restored.key);
	});

	test("can get the number of secret versions", async () => {
		await vaultConnector.setSecret(TEST_SECRET_NAME, { key: "value" });
		const versions = await vaultConnector.getSecretVersions(TEST_SECRET_NAME);
		expect(versions).toBeDefined();
		expect(versions.length).toBeGreaterThanOrEqual(1);
	});
});
