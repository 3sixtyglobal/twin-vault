// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
// Tests for the EntityStorageVaultConnector encrypted data layout.
import { Converter, RandomHelper } from "@twin.org/core";
import { ChaCha20Poly1305 } from "@twin.org/crypto";
import { MemoryEntityStorageConnector } from "@twin.org/entity-storage-connector-memory";
import { EntityStorageConnectorFactory } from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import { VaultEncryptionType, VaultKeyType } from "@twin.org/vault-models";
import type { VaultKey } from "../src/entities/vaultKey.js";
import type { VaultSecret } from "../src/entities/vaultSecret.js";
import { EntityStorageVaultConnector } from "../src/entityStorageVaultConnector.js";
import { initSchema } from "../src/schema.js";

const TEST_KEY_NAME = `test-format-key-${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_KEY_NAME_2 = `test-format-key-2-${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_DATA = Converter.utf8ToBytes("test-data");
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;

let vaultConnector: EntityStorageVaultConnector;
let vaultKeyEntityStorageConnector: MemoryEntityStorageConnector<VaultKey>;
let vaultSecretEntityStorageConnector: MemoryEntityStorageConnector<VaultSecret>;

describe("EntityStorageVaultConnector encryption format", () => {
	beforeAll(() => {
		initSchema();
	});

	beforeEach(() => {
		vaultKeyEntityStorageConnector = new MemoryEntityStorageConnector<VaultKey>({
			entitySchema: nameof<VaultKey>(),
			config: { storageKey: "vault-key" }
		});
		vaultSecretEntityStorageConnector = new MemoryEntityStorageConnector<VaultSecret>({
			entitySchema: nameof<VaultSecret>(),
			config: { storageKey: "vault-secret" }
		});
		EntityStorageConnectorFactory.register("vault-key", () => vaultKeyEntityStorageConnector);
		EntityStorageConnectorFactory.register("vault-secret", () => vaultSecretEntityStorageConnector);
		vaultConnector = new EntityStorageVaultConnector();
	});

	afterEach(async () => {
		EntityStorageConnectorFactory.unregister("vault-key");
		EntityStorageConnectorFactory.unregister("vault-secret");
		await vaultKeyEntityStorageConnector.teardown();
		await vaultSecretEntityStorageConnector.teardown();
	});

	test("can encrypt data as a nonce followed by the payload of the key", async () => {
		const symmetricKey = await vaultConnector.createKey(
			TEST_KEY_NAME,
			VaultKeyType.ChaCha20Poly1305
		);
		const encrypted = await vaultConnector.encrypt(
			TEST_KEY_NAME,
			VaultEncryptionType.ChaCha20Poly1305,
			TEST_DATA
		);
		expect(encrypted.length).toEqual(NONCE_LENGTH + TEST_DATA.length + TAG_LENGTH);

		const cipher = new ChaCha20Poly1305(symmetricKey, encrypted.slice(0, NONCE_LENGTH));
		expect(cipher.encrypt(TEST_DATA)).toEqual(encrypted.slice(NONCE_LENGTH));
	});

	test("can decrypt data locally with the exported key of an added key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
		const key = await vaultConnector.getKey(TEST_KEY_NAME);
		await vaultConnector.addKey(TEST_KEY_NAME_2, key.type, key.privateKey as Uint8Array);
		const encrypted = await vaultConnector.encrypt(
			TEST_KEY_NAME,
			VaultEncryptionType.ChaCha20Poly1305,
			TEST_DATA
		);

		const key2 = await vaultConnector.getKey(TEST_KEY_NAME_2);
		const cipher = new ChaCha20Poly1305(
			key2.privateKey as Uint8Array,
			encrypted.slice(0, NONCE_LENGTH)
		);
		expect(cipher.decrypt(encrypted.slice(NONCE_LENGTH))).toEqual(TEST_DATA);
	});
});
