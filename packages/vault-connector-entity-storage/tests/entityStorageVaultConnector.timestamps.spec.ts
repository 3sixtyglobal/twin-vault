// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
// Tests for the EntityStorageVaultConnector created and modified timestamps.
import { Converter, RandomHelper } from "@twin.org/core";
import { EntitySchemaFactory, EntitySchemaHelper } from "@twin.org/entity";
import { MemoryEntityStorageConnector } from "@twin.org/entity-storage-connector-memory";
import { EntityStorageConnectorFactory } from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import { VaultKeyType } from "@twin.org/vault-models";
import type { VaultKey } from "../src/entities/vaultKey.js";
import type { VaultKeyV0 } from "../src/entities/vaultKeyV0.js";
import type { VaultSecret } from "../src/entities/vaultSecret.js";
import type { VaultSecretV0 } from "../src/entities/vaultSecretV0.js";
import { EntityStorageVaultConnector } from "../src/entityStorageVaultConnector.js";
import { initSchema } from "../src/schema.js";

const TEST_KEY_NAME = `test-timestamp-key-${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_KEY_NAME_2 = `test-timestamp-key-2-${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_SECRET_NAME = `test-timestamp-secret-${Converter.bytesToHex(RandomHelper.generate(8))}`;
const CREATED_TIME = Date.UTC(2026, 0, 1, 10, 0, 0);
const MODIFIED_TIME = Date.UTC(2026, 0, 2, 12, 30, 0);

let vaultConnector: EntityStorageVaultConnector;
let vaultKeyEntityStorageConnector: MemoryEntityStorageConnector<VaultKey>;
let vaultSecretEntityStorageConnector: MemoryEntityStorageConnector<VaultSecret>;

describe("EntityStorageVaultConnector timestamps", () => {
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
		vi.spyOn(Date, "now").mockReturnValue(CREATED_TIME);
	});

	afterEach(async () => {
		vi.restoreAllMocks();
		EntityStorageConnectorFactory.unregister("vault-key");
		EntityStorageConnectorFactory.unregister("vault-secret");
		await vaultKeyEntityStorageConnector.teardown();
		await vaultSecretEntityStorageConnector.teardown();
	});

	test("registers version 1 schemas alongside the version 0 schemas", () => {
		expect(EntitySchemaHelper.getVersion(EntitySchemaFactory.get(nameof<VaultKey>()))).toEqual(1);
		expect(EntitySchemaHelper.getVersion(EntitySchemaFactory.get(nameof<VaultKeyV0>()))).toEqual(0);
		expect(EntitySchemaHelper.getVersion(EntitySchemaFactory.get(nameof<VaultSecret>()))).toEqual(
			1
		);
		expect(EntitySchemaHelper.getVersion(EntitySchemaFactory.get(nameof<VaultSecretV0>()))).toEqual(
			0
		);
	});

	test("can set the timestamps when creating a key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const stored = await vaultKeyEntityStorageConnector.get(TEST_KEY_NAME);
		expect(stored?.dateCreated).toEqual(new Date(CREATED_TIME).toISOString());
		expect(stored?.dateModified).toEqual(new Date(CREATED_TIME).toISOString());
	});

	test("can set the timestamps when adding a key", async () => {
		await vaultConnector.addKey(
			TEST_KEY_NAME,
			VaultKeyType.ChaCha20Poly1305,
			RandomHelper.generate(32)
		);
		const stored = await vaultKeyEntityStorageConnector.get(TEST_KEY_NAME);
		expect(stored?.dateCreated).toEqual(new Date(CREATED_TIME).toISOString());
		expect(stored?.dateModified).toEqual(new Date(CREATED_TIME).toISOString());
	});

	test("can keep the created timestamp and update the modified timestamp when renaming a key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		vi.spyOn(Date, "now").mockReturnValue(MODIFIED_TIME);
		await vaultConnector.renameKey(TEST_KEY_NAME, TEST_KEY_NAME_2);
		const stored = await vaultKeyEntityStorageConnector.get(TEST_KEY_NAME_2);
		expect(stored?.dateCreated).toEqual(new Date(CREATED_TIME).toISOString());
		expect(stored?.dateModified).toEqual(new Date(MODIFIED_TIME).toISOString());
	});

	test("can set the timestamps when storing a secret", async () => {
		await vaultConnector.setSecret(TEST_SECRET_NAME, { foo: "bar" });
		const stored = await vaultSecretEntityStorageConnector.get(TEST_SECRET_NAME);
		expect(stored?.dateCreated).toEqual(new Date(CREATED_TIME).toISOString());
		expect(stored?.dateModified).toEqual(new Date(CREATED_TIME).toISOString());
	});

	test("can keep the created timestamp and update the modified timestamp when overwriting a secret", async () => {
		await vaultConnector.setSecret(TEST_SECRET_NAME, { foo: "bar" });
		vi.spyOn(Date, "now").mockReturnValue(MODIFIED_TIME);
		await vaultConnector.setSecret(TEST_SECRET_NAME, { foo: "baz" });
		const stored = await vaultSecretEntityStorageConnector.get(TEST_SECRET_NAME);
		expect(stored?.data).toEqual({ foo: "baz" });
		expect(stored?.dateCreated).toEqual(new Date(CREATED_TIME).toISOString());
		expect(stored?.dateModified).toEqual(new Date(MODIFIED_TIME).toISOString());
	});

	test("can read a key stored without timestamps", async () => {
		await vaultKeyEntityStorageConnector.set({
			id: TEST_KEY_NAME,
			type: VaultKeyType.ChaCha20Poly1305,
			privateKey: Converter.bytesToBase64(RandomHelper.generate(32))
		});
		expect(await vaultConnector.getKeyType(TEST_KEY_NAME)).toEqual(VaultKeyType.ChaCha20Poly1305);
	});

	test("can read a secret stored without timestamps", async () => {
		await vaultSecretEntityStorageConnector.set({ id: TEST_SECRET_NAME, data: { foo: "bar" } });
		expect(await vaultConnector.getSecret(TEST_SECRET_NAME)).toEqual({ foo: "bar" });
	});
});
