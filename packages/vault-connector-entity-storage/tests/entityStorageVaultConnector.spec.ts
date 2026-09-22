// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { AlreadyExistsError, Converter, RandomHelper, StringHelper } from "@twin.org/core";
import { Ed25519 } from "@twin.org/crypto";
import { MemoryEntityStorageConnector } from "@twin.org/entity-storage-connector-memory";
import { EntityStorageConnectorFactory } from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import { VaultEncryptionType, VaultKeyType } from "@twin.org/vault-models";
import type { VaultKey } from "../src/entities/vaultKey.js";
import type { VaultSecret } from "../src/entities/vaultSecret.js";
import { EntityStorageVaultConnector } from "../src/entityStorageVaultConnector.js";
import { initSchema } from "../src/schema.js";

// NOTE: This test file must be kept in sync with:
// packages/vault-connector-hashicorp/tests/hashicorpVaultConnector.spec.ts
// Shared tests are identical in both files (apart from connector setup).
// When adding, removing, or modifying tests here, apply the same
// change to the other file. Implementation-specific tests live in separate spec files.

const TEST_KEY_NAME = `test-key=+/@!£$%^&*()${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_KEY_NAME_2 = `test-key-2=+/@!£$%^&*()${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_SECRET_NAME =
	"bootstrap-4d8819601e1955d4d2a1c98608629c58eb579692fb8c1b49b258726e31e8a8d4_mnemonic'";
const TEST_RESTORE_KEY_NAME =
	"did:iota:tst:0xac07260b1d822a6906018f3870aea8e50cf59fc46d29feffdf141997d25917c2/temp-vm-dkwsdrKHIM_7L1dBs-zWsA";
const TEST_RESTORE_NEW_KEY_NAME =
	"did:iota:tst:0xac07260b1d822a6906018f3870aea8e50cf59fc46d29feffdf141997d25917c2/immutable-proof";

let vaultConnector: EntityStorageVaultConnector;
let vaultKeyEntityStorageConnector: MemoryEntityStorageConnector<VaultKey>;
let vaultSecretEntityStorageConnector: MemoryEntityStorageConnector<VaultSecret>;

describe("EntityStorageVaultConnector", () => {
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

	test("can construct with dependencies", async () => {
		expect(new EntityStorageVaultConnector()).toBeDefined();
	});

	test("can fail to store a secret with no secret name", async () => {
		await expect(
			vaultConnector.setSecret(undefined as unknown as string, undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to store a secret with no data", async () => {
		await expect(
			vaultConnector.setSecret(TEST_SECRET_NAME, undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.undefined",
			properties: { property: "data", value: "undefined" }
		});
	});

	test("can store a secret", async () => {
		await vaultConnector.setSecret(TEST_SECRET_NAME, { foo: "bar" });
		expect(await vaultConnector.secretExists(TEST_SECRET_NAME)).toBeTruthy();
	});

	test("can fail to get a secret with no secret name", async () => {
		await expect(vaultConnector.getSecret(undefined as unknown as string)).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to get a secret that does not exist", async () => {
		await expect(vaultConnector.getSecret(TEST_SECRET_NAME)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_SECRET_NAME }
		});
	});

	test("can get a secret", async () => {
		await vaultConnector.setSecret(TEST_SECRET_NAME, { foo: "bar" });
		const secret = await vaultConnector.getSecret(TEST_SECRET_NAME);
		expect(secret).toEqual({ foo: "bar" });
	});

	test("can set and get a secret that is a string", async () => {
		await vaultConnector.setSecret(TEST_SECRET_NAME, "foo");
		const retrieved = await vaultConnector.getSecret<string>(TEST_SECRET_NAME);
		expect(retrieved).toEqual("foo");
	});

	test("can set and get a secret that is an object", async () => {
		const secretData = { key: "value", number: 42 };
		await vaultConnector.setSecret(TEST_SECRET_NAME, secretData);
		const retrieved = await vaultConnector.getSecret<typeof secretData>(TEST_SECRET_NAME);
		expect(retrieved.key).toEqual(secretData.key);
		expect(retrieved.number).toEqual(secretData.number);
	});

	test("can fail to check if a secret exists with no secret name", async () => {
		await expect(vaultConnector.secretExists(undefined as unknown as string)).rejects.toMatchObject(
			{
				name: "GuardError",
				message: "guard.string",
				properties: { property: "name", value: "undefined" }
			}
		);
	});

	test("can check a secret does not exist", async () => {
		expect(await vaultConnector.secretExists(TEST_SECRET_NAME)).toBeFalsy();
	});

	test("can check a secret exists", async () => {
		await vaultConnector.setSecret(TEST_SECRET_NAME, { foo: "bar" });
		expect(await vaultConnector.secretExists(TEST_SECRET_NAME)).toBeTruthy();
	});

	test("can fail to remove a secret with no secret name", async () => {
		await expect(vaultConnector.removeSecret(undefined as unknown as string)).rejects.toMatchObject(
			{
				name: "GuardError",
				message: "guard.string",
				properties: { property: "name", value: "undefined" }
			}
		);
	});

	test("can fail to remove a secret that does not exist", async () => {
		await expect(vaultConnector.removeSecret(TEST_SECRET_NAME)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_SECRET_NAME }
		});
	});

	test("can remove a secret", async () => {
		await vaultConnector.setSecret(TEST_SECRET_NAME, { foo: "bar" });
		await vaultConnector.removeSecret(TEST_SECRET_NAME);
		await expect(vaultConnector.getSecret(TEST_SECRET_NAME)).rejects.toThrowError();
	});

	test("can fail to create a key with no key name", async () => {
		await expect(
			vaultConnector.createKey(undefined as unknown as string, undefined as unknown as VaultKeyType)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to create a key with no key type", async () => {
		await expect(
			vaultConnector.createKey(TEST_KEY_NAME, undefined as unknown as VaultKeyType)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.arrayOneOf",
			properties: { property: "type", value: "undefined" }
		});
	});

	test("can fail to create a key if it already exists", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		await expect(
			vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519)
		).rejects.toThrowError(AlreadyExistsError);
	});

	test("can create a key", async () => {
		const publicKey = await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		expect(publicKey).toBeDefined();
		expect(publicKey.length).toBeGreaterThan(0);
	});

	test("can fail to add a key with no key name", async () => {
		await expect(
			vaultConnector.addKey(
				undefined as unknown as string,
				undefined as unknown as VaultKeyType,
				undefined as unknown as Uint8Array,
				undefined
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to add a key with no key type", async () => {
		await expect(
			vaultConnector.addKey(
				TEST_KEY_NAME,
				undefined as unknown as VaultKeyType,
				undefined as unknown as Uint8Array,
				undefined
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.arrayOneOf",
			properties: { property: "type", value: "undefined" }
		});
	});

	test("can fail to add a key with no private key", async () => {
		await expect(
			vaultConnector.addKey(
				TEST_KEY_NAME,
				VaultKeyType.Ed25519,
				undefined as unknown as Uint8Array,
				undefined
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.uint8Array",
			properties: { property: "privateKey", value: "undefined" }
		});
	});

	test("can fail to add a key if it already exists", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		await expect(
			vaultConnector.addKey(TEST_KEY_NAME, VaultKeyType.Ed25519, new Uint8Array(), new Uint8Array())
		).rejects.toMatchObject({
			name: "AlreadyExistsError",
			properties: { existingId: TEST_KEY_NAME }
		});
	});

	test("can add a key", async () => {
		const privateKey = Converter.base64ToBytes("vOpvrUcuiDJF09hoe9AWa4OUqcNqr6RpGOuj/A57gag=");
		const publicKey = Converter.base64ToBytes("KylrGqIEfx7mRdQKNhu+o0l0MU/WilWkOQ2YhkhYC5Y=");
		await vaultConnector.addKey(TEST_KEY_NAME, VaultKeyType.Ed25519, privateKey, publicKey);
		const key = await vaultConnector.getKey(TEST_KEY_NAME);
		expect(key.type).toEqual(VaultKeyType.Ed25519);
	});

	test("can add and get asymmetric key ed25519", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const key = await vaultConnector.getKey(TEST_KEY_NAME);
		await vaultConnector.addKey(
			TEST_KEY_NAME_2,
			key.type,
			key.privateKey as Uint8Array,
			key.publicKey
		);
		const signed = await vaultConnector.sign(TEST_KEY_NAME, Converter.utf8ToBytes("test-data"));
		const signed2 = await vaultConnector.sign(TEST_KEY_NAME_2, Converter.utf8ToBytes("test-data"));
		expect(signed).toEqual(signed2);
	});

	test("can add and get symmetric key chacha20poly1305", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
		const key = await vaultConnector.getKey(TEST_KEY_NAME);
		await vaultConnector.addKey(
			TEST_KEY_NAME_2,
			key.type,
			key.privateKey as Uint8Array,
			key.publicKey
		);
		const encrypted = await vaultConnector.encrypt(
			TEST_KEY_NAME,
			VaultEncryptionType.ChaCha20Poly1305,
			Converter.utf8ToBytes("test-data")
		);
		const decrypted = await vaultConnector.decrypt(
			TEST_KEY_NAME_2,
			VaultEncryptionType.ChaCha20Poly1305,
			encrypted
		);
		expect(decrypted).toEqual(Converter.utf8ToBytes("test-data"));
	});

	test("can fail to get a key with no key name", async () => {
		await expect(vaultConnector.getKey(undefined as unknown as string)).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to get a key if it doesn't exist", async () => {
		await expect(vaultConnector.getKey(TEST_KEY_NAME)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can get an asymmetric key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const key = await vaultConnector.getKey(TEST_KEY_NAME);
		expect(key.type).toEqual(VaultKeyType.Ed25519);
		expect(key.publicKey).toBeDefined();
		expect(key.publicKey?.length).toBeGreaterThan(0);
		expect(key.privateKey).toBeDefined();
		expect(key.privateKey?.length).toBeGreaterThan(0);
	});

	test("can get a symmetric key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
		const key = await vaultConnector.getKey(TEST_KEY_NAME);
		expect(key.type).toEqual(VaultKeyType.ChaCha20Poly1305);
		expect(key.privateKey).toBeDefined();
		expect(key.privateKey?.length).toBeGreaterThan(0);
		expect(key.publicKey).toBeUndefined();
	});

	test("can get only public component of asymmetric key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const key = await vaultConnector.getKey(TEST_KEY_NAME, "public");
		expect(key.type).toEqual(VaultKeyType.Ed25519);
		expect(key.publicKey).toBeDefined();
		expect(key.publicKey?.length).toBeGreaterThan(0);
		expect(key.privateKey).toBeUndefined();
	});

	test("can get only private component of asymmetric key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const key = await vaultConnector.getKey(TEST_KEY_NAME, "private");
		expect(key.type).toEqual(VaultKeyType.Ed25519);
		expect(key.privateKey).toBeDefined();
		expect(key.privateKey?.length).toBeGreaterThan(0);
		expect(key.publicKey).toBeUndefined();
	});

	test("can fail to get private component of symmetric key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
		await expect(vaultConnector.getKey(TEST_KEY_NAME, "private")).rejects.toMatchObject({
			name: "GeneralError",
			message: `${StringHelper.camelCase(vaultConnector.className())}.symmetricKeyHasNoPrivateKey`,
			properties: { name: TEST_KEY_NAME }
		});
	});

	test("can fail to get key type with no key name", async () => {
		await expect(vaultConnector.getKeyType(undefined as unknown as string)).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to get key type if key doesn't exist", async () => {
		await expect(vaultConnector.getKeyType(TEST_KEY_NAME)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can get key type for Ed25519 key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		expect(await vaultConnector.getKeyType(TEST_KEY_NAME)).toEqual(VaultKeyType.Ed25519);
	});

	test("can get key type for ChaCha20Poly1305 key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
		expect(await vaultConnector.getKeyType(TEST_KEY_NAME)).toEqual(VaultKeyType.ChaCha20Poly1305);
	});

	test("can fail to check if a key exists with no key name", async () => {
		await expect(vaultConnector.keyExists(undefined as unknown as string)).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can check a key does not exist", async () => {
		expect(await vaultConnector.keyExists(TEST_KEY_NAME)).toBeFalsy();
	});

	test("can check a key exists", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		expect(await vaultConnector.keyExists(TEST_KEY_NAME)).toBeTruthy();
	});

	test("can fail to rename a key with no key name", async () => {
		await expect(
			vaultConnector.renameKey(undefined as unknown as string, undefined as unknown as string)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to rename a key with no new key name", async () => {
		await expect(
			vaultConnector.renameKey("foo", undefined as unknown as string)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "newName", value: "undefined" }
		});
	});

	test("can fail to rename a key if it doesn't exist", async () => {
		await expect(vaultConnector.renameKey(TEST_KEY_NAME, "foo")).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can fail to rename a key if the new name already exists", async () => {
		await vaultConnector.createKey(TEST_RESTORE_KEY_NAME, VaultKeyType.Ed25519);
		await vaultConnector.createKey(TEST_RESTORE_NEW_KEY_NAME, VaultKeyType.Ed25519);
		await expect(
			vaultConnector.renameKey(TEST_RESTORE_KEY_NAME, TEST_RESTORE_NEW_KEY_NAME)
		).rejects.toMatchObject({
			name: "AlreadyExistsError",
			properties: { existingId: TEST_RESTORE_NEW_KEY_NAME }
		});
	});

	test("can rename a key", async () => {
		await vaultConnector.createKey(TEST_RESTORE_KEY_NAME, VaultKeyType.Ed25519);
		await vaultConnector.renameKey(TEST_RESTORE_KEY_NAME, TEST_RESTORE_NEW_KEY_NAME);
		expect(await vaultConnector.keyExists(TEST_RESTORE_KEY_NAME)).toBeFalsy();
		expect(await vaultConnector.keyExists(TEST_RESTORE_NEW_KEY_NAME)).toBeTruthy();
	});

	test("can fail to remove a key with no key name", async () => {
		await expect(vaultConnector.removeKey(undefined as unknown as string)).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to remove a key if it doesn't exist", async () => {
		await expect(vaultConnector.removeKey(TEST_KEY_NAME)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can remove a key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		await vaultConnector.removeKey(TEST_KEY_NAME);
		expect(await vaultConnector.keyExists(TEST_KEY_NAME)).toBeFalsy();
	});

	test("can fail to sign with a key with no key name", async () => {
		await expect(
			vaultConnector.sign(undefined as unknown as string, undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to sign with a key with no data", async () => {
		await expect(
			vaultConnector.sign(TEST_KEY_NAME, undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.uint8Array",
			properties: { property: "data", value: "undefined" }
		});
	});

	test("can fail to sign with a key if it doesn't exist", async () => {
		await expect(vaultConnector.sign(TEST_KEY_NAME, new Uint8Array())).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can sign data with a key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const signature = await vaultConnector.sign(TEST_KEY_NAME, new Uint8Array([1, 2, 3, 4, 5]));
		expect(signature).toBeDefined();
		expect(signature.length).toBeGreaterThan(0);
	});

	test("can fail to verify with a key with no key name", async () => {
		await expect(
			vaultConnector.verify(
				undefined as unknown as string,
				undefined as unknown as Uint8Array,
				undefined as unknown as Uint8Array
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to verify with a key with no data", async () => {
		await expect(
			vaultConnector.verify(
				TEST_KEY_NAME,
				undefined as unknown as Uint8Array,
				undefined as unknown as Uint8Array
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.uint8Array",
			properties: { property: "data", value: "undefined" }
		});
	});

	test("can fail to verify with a key with no signature", async () => {
		await expect(
			vaultConnector.verify(TEST_KEY_NAME, new Uint8Array(), undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.uint8Array",
			properties: { property: "signature", value: "undefined" }
		});
	});

	test("can fail to verify with a key if it doesn't exist", async () => {
		await expect(
			vaultConnector.verify(TEST_KEY_NAME, new Uint8Array(), new Uint8Array())
		).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can verify signature with a key", async () => {
		const publicKey = await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const data = new Uint8Array([1, 2, 3, 4, 5]);
		const signature = await vaultConnector.sign(TEST_KEY_NAME, data);
		expect(await vaultConnector.verify(TEST_KEY_NAME, data, signature)).toBe(true);
		expect(Ed25519.verify(publicKey, data, signature)).toBe(true);
	});

	test("can fail to verify signature with a key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const data = new Uint8Array([1, 2, 3, 4, 5]);
		const signature = await vaultConnector.sign(TEST_KEY_NAME, data);
		expect(
			await vaultConnector.verify(TEST_KEY_NAME, new Uint8Array([5, 4, 3, 2, 1]), signature)
		).toBe(false);
	});

	test("can sign and verify data", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.Ed25519);
		const data = Converter.utf8ToBytes("test-data");
		const signature = await vaultConnector.sign(TEST_KEY_NAME, data);
		expect(await vaultConnector.verify(TEST_KEY_NAME, data, signature)).toBe(true);
	});

	test("can fail to encrypt with a key with no key name", async () => {
		await expect(
			vaultConnector.encrypt(
				undefined as unknown as string,
				undefined as unknown as VaultEncryptionType,
				undefined as unknown as Uint8Array
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to encrypt with a key with no encryption type", async () => {
		await expect(
			vaultConnector.encrypt(
				TEST_KEY_NAME,
				undefined as unknown as VaultEncryptionType,
				undefined as unknown as Uint8Array
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.arrayOneOf",
			properties: { property: "encryptionType", value: "undefined" }
		});
	});

	test("can fail to encrypt with a key with no data", async () => {
		await expect(
			vaultConnector.encrypt(
				TEST_KEY_NAME,
				VaultEncryptionType.ChaCha20Poly1305,
				undefined as unknown as Uint8Array
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.uint8Array",
			properties: { property: "data", value: "undefined" }
		});
	});

	test("can fail to encrypt with a key if it doesn't exist", async () => {
		await expect(
			vaultConnector.encrypt(TEST_KEY_NAME, VaultEncryptionType.ChaCha20Poly1305, new Uint8Array())
		).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can encrypt with a key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
		const encrypted = await vaultConnector.encrypt(
			TEST_KEY_NAME,
			VaultEncryptionType.ChaCha20Poly1305,
			new Uint8Array([1, 2, 3, 4, 5])
		);
		expect(encrypted.length).toBeGreaterThan(5);
	});

	test("can fail to decrypt with a key with no key name", async () => {
		await expect(
			vaultConnector.decrypt(
				undefined as unknown as string,
				undefined as unknown as VaultEncryptionType,
				undefined as unknown as Uint8Array
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: { property: "name", value: "undefined" }
		});
	});

	test("can fail to decrypt with a key with no encryption type", async () => {
		await expect(
			vaultConnector.decrypt(
				TEST_KEY_NAME,
				undefined as unknown as VaultEncryptionType,
				undefined as unknown as Uint8Array
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.arrayOneOf",
			properties: { property: "encryptionType", value: "undefined" }
		});
	});

	test("can fail to decrypt with a key with no data", async () => {
		await expect(
			vaultConnector.decrypt(
				TEST_KEY_NAME,
				VaultEncryptionType.ChaCha20Poly1305,
				undefined as unknown as Uint8Array
			)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.uint8Array",
			properties: { property: "encryptedData", value: "undefined" }
		});
	});

	test("can fail to decrypt with a key if it doesn't exist", async () => {
		await expect(
			vaultConnector.decrypt(TEST_KEY_NAME, VaultEncryptionType.ChaCha20Poly1305, new Uint8Array())
		).rejects.toMatchObject({
			name: "NotFoundError",
			properties: { notFoundId: TEST_KEY_NAME }
		});
	});

	test("can decrypt with a key", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
		const data = new Uint8Array([1, 2, 3, 4, 5]);
		const encrypted = await vaultConnector.encrypt(
			TEST_KEY_NAME,
			VaultEncryptionType.ChaCha20Poly1305,
			data
		);
		const decrypted = await vaultConnector.decrypt(
			TEST_KEY_NAME,
			VaultEncryptionType.ChaCha20Poly1305,
			encrypted
		);
		expect(decrypted).toEqual(data);
	});

	test("can encrypt and decrypt data", async () => {
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
		const data = Converter.utf8ToBytes("test-data");
		const encryptedData = await vaultConnector.encrypt(
			TEST_KEY_NAME,
			VaultEncryptionType.ChaCha20Poly1305,
			data
		);
		expect(encryptedData.length).toBeGreaterThan(data.length);
		const decryptedData = await vaultConnector.decrypt(
			TEST_KEY_NAME,
			VaultEncryptionType.ChaCha20Poly1305,
			encryptedData
		);
		expect(decryptedData).toEqual(data);
	});

	test("can perform key operations with a prefix", async () => {
		const connector = new EntityStorageVaultConnector({ config: { prefix: "foo" } });
		const prefixKey = "key-with-prefix";
		await connector.createKey(prefixKey, VaultKeyType.ChaCha20Poly1305);
		const key = await connector.getKey(prefixKey);
		expect(key.type).toEqual(VaultKeyType.ChaCha20Poly1305);
		const encrypted = await connector.encrypt(
			prefixKey,
			VaultEncryptionType.ChaCha20Poly1305,
			new Uint8Array([1, 2, 3, 4, 5])
		);
		expect(encrypted.length).toBeGreaterThan(5);
		const decrypted = await connector.decrypt(
			prefixKey,
			VaultEncryptionType.ChaCha20Poly1305,
			encrypted
		);
		expect(decrypted).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
		await connector.createKey(`${prefixKey}-1`, VaultKeyType.Ed25519);
		const signature = await connector.sign(`${prefixKey}-1`, new Uint8Array([1, 2, 3, 4, 5]));
		const verified = await connector.verify(
			`${prefixKey}-1`,
			new Uint8Array([1, 2, 3, 4, 5]),
			signature
		);
		expect(verified).toEqual(true);
		await connector.removeKey(`${prefixKey}-1`);
		await connector.removeKey(prefixKey);
	});

	test("can perform secret operations with a prefix", async () => {
		const connector = new EntityStorageVaultConnector({ config: { prefix: "foo" } });
		const prefixSecret = "secret-with-prefix";
		await connector.setSecret(prefixSecret, { foo: "bar" });
		const secret = await connector.getSecret(prefixSecret);
		expect(secret).toEqual({ foo: "bar" });
		await connector.removeSecret(prefixSecret);
	});
});
