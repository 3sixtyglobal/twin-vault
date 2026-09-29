// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
// Tests for the HashicorpVaultConnector key metadata cache.
import { Converter, RandomHelper } from "@twin.org/core";
import { VaultEncryptionType, VaultKeyType } from "@twin.org/vault-models";
import { FetchHelper, HttpMethod } from "@twin.org/web";
import { cleanupKeys, TEST_VAULT_CONFIG } from "./setupTestEnv.js";
import { HashicorpVaultConnector } from "../src/hashicorpVaultConnector.js";

const TEST_KEY_NAME = `test-cache-key-${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_KEY_NAME_2 = `test-cache-key-2-${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_DATA = new Uint8Array([1, 2, 3, 4, 5]);

let vaultConnector: HashicorpVaultConnector;

/**
 * Build the transit metadata url of a key.
 * @param name The key name.
 * @returns The url.
 */
function keyUrl(name: string): string {
	return `${TEST_VAULT_CONFIG.endpoint}/${TEST_VAULT_CONFIG.apiVersion}/${TEST_VAULT_CONFIG.transitMountPath}/keys/${name}`;
}

/**
 * Count the metadata reads of a key among the recorded fetch calls.
 * @param calls The recorded fetch calls.
 * @param name The key name.
 * @returns The number of GET calls for the key url.
 */
function keyReadCount(calls: unknown[][], name: string): number {
	return calls.filter(call => call[1] === keyUrl(name) && call[2] === HttpMethod.GET).length;
}

describe("HashicorpVaultConnector key metadata cache", () => {
	beforeEach(async () => {
		vaultConnector = new HashicorpVaultConnector({ config: TEST_VAULT_CONFIG });
		await vaultConnector.bootstrap();
		await cleanupKeys([TEST_KEY_NAME, TEST_KEY_NAME_2]);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	test("can read the key metadata once across getKeyType, sign and verify", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const fetchJsonSpy = vi.spyOn(FetchHelper, "fetchJson");

		await vaultConnector.getKeyType(TEST_KEY_NAME);
		const signature = await vaultConnector.sign(TEST_KEY_NAME, TEST_DATA);
		await vaultConnector.verify(TEST_KEY_NAME, TEST_DATA, signature);
		await vaultConnector.getKeyType(TEST_KEY_NAME);

		expect(fetchJsonSpy).toHaveBeenCalledWith(
			HashicorpVaultConnector.CLASS_NAME,
			keyUrl(TEST_KEY_NAME),
			HttpMethod.GET,
			undefined,
			expect.objectContaining({
				headers: expect.objectContaining({ "X-Vault-Token": TEST_VAULT_CONFIG.token })
			})
		);
		expect(keyReadCount(fetchJsonSpy.mock.calls, TEST_KEY_NAME)).toEqual(1);
	});

	test("can fail to encrypt with a mismatched key type using the cached metadata", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const fetchJsonSpy = vi.spyOn(FetchHelper, "fetchJson");

		await vaultConnector.getKeyType(TEST_KEY_NAME);
		await expect(
			vaultConnector.encrypt(TEST_KEY_NAME, VaultEncryptionType.ChaCha20Poly1305, TEST_DATA)
		).rejects.toMatchObject({
			name: "GeneralError",
			message: "hashicorpVaultConnector.keyTypeMismatch"
		});
		expect(keyReadCount(fetchJsonSpy.mock.calls, TEST_KEY_NAME)).toEqual(1);
	});

	test("can fail to sign with a key after it has been removed", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		await vaultConnector.sign(TEST_KEY_NAME, TEST_DATA);
		await vaultConnector.removeKey(TEST_KEY_NAME);

		await expect(vaultConnector.sign(TEST_KEY_NAME, TEST_DATA)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can sign with the new name and fail with the old name after a rename", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		await vaultConnector.sign(TEST_KEY_NAME, TEST_DATA);
		await vaultConnector.renameKey(TEST_KEY_NAME, TEST_KEY_NAME_2);

		const signature = await vaultConnector.sign(TEST_KEY_NAME_2, TEST_DATA);
		expect(await vaultConnector.verify(TEST_KEY_NAME_2, TEST_DATA, signature)).toEqual(true);
		await expect(vaultConnector.sign(TEST_KEY_NAME, TEST_DATA)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can fail to sign with a key that does not exist on every call", async () => {
		const fetchJsonSpy = vi.spyOn(FetchHelper, "fetchJson");
		const missingKeyError = {
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		};

		await expect(vaultConnector.sign(TEST_KEY_NAME, TEST_DATA)).rejects.toMatchObject(
			missingKeyError
		);
		await expect(vaultConnector.sign(TEST_KEY_NAME, TEST_DATA)).rejects.toMatchObject(
			missingKeyError
		);
		expect(keyReadCount(fetchJsonSpy.mock.calls, TEST_KEY_NAME)).toEqual(2);
	});

	test("can read the key metadata on every call when the cache is disabled", async () => {
		const uncachedConnector = new HashicorpVaultConnector({
			config: { ...TEST_VAULT_CONFIG, keyMetadataCacheTtlMs: 0 }
		});
		await uncachedConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const fetchJsonSpy = vi.spyOn(FetchHelper, "fetchJson");

		await uncachedConnector.sign(TEST_KEY_NAME, TEST_DATA);
		await uncachedConnector.sign(TEST_KEY_NAME, TEST_DATA);
		expect(keyReadCount(fetchJsonSpy.mock.calls, TEST_KEY_NAME)).toEqual(2);
	});

	test("can read the key metadata again after the ttl expires", async () => {
		const shortTtlConnector = new HashicorpVaultConnector({
			config: { ...TEST_VAULT_CONFIG, keyMetadataCacheTtlMs: 100 }
		});
		await shortTtlConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const fetchJsonSpy = vi.spyOn(FetchHelper, "fetchJson");

		await shortTtlConnector.sign(TEST_KEY_NAME, TEST_DATA);
		await new Promise(resolve => {
			setTimeout(resolve, 150);
		});
		await shortTtlConnector.sign(TEST_KEY_NAME, TEST_DATA);
		expect(keyReadCount(fetchJsonSpy.mock.calls, TEST_KEY_NAME)).toEqual(2);
	});

	test("can read the key metadata on every call after stop", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const fetchJsonSpy = vi.spyOn(FetchHelper, "fetchJson");

		await vaultConnector.stop();
		await vaultConnector.sign(TEST_KEY_NAME, TEST_DATA);
		await vaultConnector.sign(TEST_KEY_NAME, TEST_DATA);
		expect(keyReadCount(fetchJsonSpy.mock.calls, TEST_KEY_NAME)).toEqual(2);
	});
});
