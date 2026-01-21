// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { AlreadyExistsError, Converter, GeneralError, RandomHelper } from "@twin.org/core";
import { ChaCha20Poly1305, Ed25519 } from "@twin.org/crypto";
import { VaultEncryptionType, VaultKeyType } from "@twin.org/vault-models";
import { cleanupKeys, cleanupSecrets, TEST_VAULT_CONFIG } from "./setupTestEnv.js";
import { HashicorpVaultConnector } from "../src/hashicorpVaultConnector.js";

const TEST_KEY_NAME = `test-key=+/@!£$%^&*()${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_KEY_NAME_2 = `test-key-2=+/@!£$%^&*()${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_SECRET_NAME =
	"bootstrap-4d8819601e1955d4d2a1c98608629c58eb579692fb8c1b49b258726e31e8a8d4_mnemonic'";
const TEST_RESTORE_KEY_NAME =
	"did:iota:tst:0xac07260b1d822a6906018f3870aea8e50cf59fc46d29feffdf141997d25917c2/temp-vm-dkwsdrKHIM_7L1dBs-zWsA";
const TEST_RESTORE_NEW_KEY_NAME =
	"did:iota:tst:0xac07260b1d822a6906018f3870aea8e50cf59fc46d29feffdf141997d25917c2/immutable-proof";

let vaultConnector: HashicorpVaultConnector;

describe("HashicorpVaultConnector", () => {
	beforeEach(async () => {
		vaultConnector = new HashicorpVaultConnector({
			config: TEST_VAULT_CONFIG
		});
		await vaultConnector.bootstrap();
		await cleanupKeys([
			TEST_KEY_NAME,
			TEST_RESTORE_KEY_NAME,
			TEST_RESTORE_NEW_KEY_NAME,
			TEST_KEY_NAME_2
		]);
		await cleanupSecrets([TEST_SECRET_NAME]);
	});

	test("can construct with dependencies", async () => {
		const vaultConnectorHealth = new HashicorpVaultConnector({
			config: TEST_VAULT_CONFIG
		});

		expect(vaultConnectorHealth).toBeDefined();
	});

	test("can fail to store a secret with no secret name", async () => {
		await expect(
			vaultConnector.setSecret(undefined as unknown as string, undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: {
				property: "name",
				value: "undefined"
			}
		});
	});

	test("can fail to store a secret with no data", async () => {
		await expect(
			vaultConnector.setSecret(TEST_SECRET_NAME, undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.undefined",
			properties: {
				property: "data",
				value: "undefined"
			}
		});
	});

	test("can fail to get a secret with no secret name", async () => {
		await expect(vaultConnector.getSecret(undefined as unknown as string)).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: {
				property: "name",
				value: "undefined"
			}
		});
	});

	test("can fail to get a secret that does not exist", async () => {
		await expect(vaultConnector.getSecret(TEST_SECRET_NAME)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: {
				notFoundId: TEST_SECRET_NAME
			}
		});
	});

	test("can fail to remove a secret with no secret name", async () => {
		await expect(vaultConnector.removeSecret(undefined as unknown as string)).rejects.toMatchObject(
			{
				name: "GuardError",
				message: "guard.string",
				properties: {
					property: "name",
					value: "undefined"
				}
			}
		);
	});

	test("can fail to remove a secret that does not exist", async () => {
		await expect(vaultConnector.removeSecret(TEST_SECRET_NAME)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: {
				notFoundId: TEST_SECRET_NAME
			}
		});
	});

	test("can set and get a secret that is a string", async () => {
		const secretName = TEST_SECRET_NAME;
		const secretData = "foo";

		await vaultConnector.setSecret(secretName, secretData);

		const retrievedSecret = await vaultConnector.getSecret<typeof secretData>(secretName);

		expect(retrievedSecret).toBeDefined();
		expect(retrievedSecret).toEqual("foo");

		await cleanupSecrets([TEST_SECRET_NAME]);
	});

	test("can set and get a secret that is an object", async () => {
		const secretName = TEST_SECRET_NAME;
		const secretData = { key: "value", number: 42 };

		await vaultConnector.setSecret(secretName, secretData);

		const retrievedSecret = await vaultConnector.getSecret<typeof secretData>(secretName);

		expect(retrievedSecret).toBeDefined();
		expect(retrievedSecret.key).toEqual(secretData.key);
		expect(retrievedSecret.number).toEqual(secretData.number);

		await cleanupSecrets([TEST_SECRET_NAME]);
	});

	test("can get the number of secret versions", async () => {
		const secretName = TEST_SECRET_NAME;
		const secretData = { key: "value", number: 42 };

		await vaultConnector.setSecret(secretName, secretData);

		const versions = await vaultConnector.getSecretVersions(secretName);

		expect(versions).toBeDefined();
		expect(versions.length).toBeGreaterThanOrEqual(1);

		await cleanupSecrets([TEST_SECRET_NAME]);
	});

	test("can remove a secret", async () => {
		const secretName = TEST_SECRET_NAME;
		const secretData = { key: "value", number: 42 };

		await vaultConnector.setSecret(secretName, secretData);
		await vaultConnector.removeSecret(secretName);

		await expect(vaultConnector.getSecret(secretName)).rejects.toThrowError();
	});

	test("can fail to create a key with no key name", async () => {
		await expect(
			vaultConnector.createKey(undefined as unknown as string, undefined as unknown as VaultKeyType)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: {
				property: "name",
				value: "undefined"
			}
		});
	});

	test("can fail to create a key with no key type", async () => {
		await expect(
			vaultConnector.createKey(TEST_KEY_NAME, undefined as unknown as VaultKeyType)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.arrayOneOf",
			properties: {
				property: "type",
				value: "undefined"
			}
		});
	});

	test("can fail to create a key if it already exists", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await cleanupKeys([TEST_KEY_NAME]);
		await vaultConnector.createKey(keyName, keyType);

		await expect(vaultConnector.createKey(keyName, keyType)).rejects.toThrowError(
			AlreadyExistsError
		);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can create and get asymmetric key ed25519", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		const publicKey = await vaultConnector.createKey(keyName, keyType);

		expect(publicKey).toBeDefined();
		expect(publicKey.length).toBeGreaterThan(0);

		const retrievedPublicKey = await vaultConnector.exportKey(keyName, "public-key");
		expect(retrievedPublicKey.key).toEqual(publicKey);

		const retrievedPrivateKey = await vaultConnector.exportKey(keyName, "signing-key");
		expect(retrievedPrivateKey.key).toBeDefined();

		const signature = Ed25519.sign(retrievedPrivateKey.key, Converter.utf8ToBytes("test-data"));
		expect(
			Ed25519.verify(retrievedPublicKey.key, Converter.utf8ToBytes("test-data"), signature)
		).toBe(true);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can create and get symmetric key chacha20poly1305", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.ChaCha20Poly1305;

		const publicKey = await vaultConnector.createKey(keyName, keyType);

		expect(publicKey).toBeDefined();
		expect(publicKey.length).toBeGreaterThan(0);

		const retrievedPublicKey = await vaultConnector.exportKey(keyName, "encryption-key");
		expect(retrievedPublicKey.key).toEqual(publicKey);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can add and get asymmetric key ed25519", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		// Create a key
		await vaultConnector.createKey(keyName, keyType);

		// Get the key details
		const key = await vaultConnector.getKey(keyName);
		expect(key).toBeDefined();

		// Add a secondary key with the same key data
		const keyName2 = TEST_KEY_NAME_2;
		await vaultConnector.addKey(keyName2, key.type, key.privateKey, key.publicKey);
		const key2 = await vaultConnector.getKey(keyName2);
		expect(key2).toBeDefined();

		// Sign data with both keys to compare the signatures
		const signed = await vaultConnector.sign(keyName, Converter.utf8ToBytes("test-data"));
		const signed2 = await vaultConnector.sign(keyName2, Converter.utf8ToBytes("test-data"));
		expect(signed).toEqual(signed2);

		await cleanupKeys([TEST_KEY_NAME, TEST_KEY_NAME_2]);
	});

	test("can add and get symmetric key chacha20poly1305", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.ChaCha20Poly1305;

		// Create a key
		await vaultConnector.createKey(keyName, keyType);

		// Get the key details
		const key = await vaultConnector.getKey(keyName);
		expect(key).toBeDefined();

		// Add a secondary key with the same key data
		const keyName2 = TEST_KEY_NAME_2;
		await vaultConnector.addKey(keyName2, key.type, key.privateKey, key.publicKey);
		const key2 = await vaultConnector.getKey(keyName2);
		expect(key2).toBeDefined();

		// Encrypt with original key
		const encrypted = await vaultConnector.encrypt(
			keyName,
			VaultEncryptionType.ChaCha20Poly1305,
			Converter.utf8ToBytes("test-data")
		);

		// And decrypt with the new key to demonstrate that the keys are interchangeable
		const decrypted = await vaultConnector.decrypt(
			keyName2,
			VaultEncryptionType.ChaCha20Poly1305,
			encrypted
		);

		// Make sure we can decrypt with the standard chacha20poly1305 implementation as well
		// The first 12 bytes are the nonce
		const chacha20poly1305 = new ChaCha20Poly1305(key2.privateKey, encrypted.slice(0, 12));
		const decrypted2 = chacha20poly1305.decrypt(encrypted.slice(12));

		expect(decrypted).toEqual(Converter.utf8ToBytes("test-data"));
		expect(decrypted2).toEqual(Converter.utf8ToBytes("test-data"));

		await cleanupKeys([TEST_KEY_NAME, TEST_KEY_NAME_2]);
	});

	test("can fail to get a key with no key name", async () => {
		await expect(vaultConnector.getKey(undefined as unknown as string)).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: {
				property: "name",
				value: "undefined"
			}
		});
	});

	test("can fail to get a key if it doesn't exist", async () => {
		await expect(vaultConnector.getKey(TEST_KEY_NAME)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: {
				notFoundId: TEST_KEY_NAME
			}
		});
	});

	test("can update key configuration to allow deletion", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(keyName, keyType);

		await vaultConnector.updateKeyConfig(keyName, true);

		const deleteConfiguration = await vaultConnector.getKeyDeleteConfiguration(keyName);

		expect(deleteConfiguration).toBeDefined();
		expect(deleteConfiguration).toEqual(true);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can remove a key", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(keyName, keyType);

		await vaultConnector.removeKey(keyName);

		await expect(vaultConnector.exportKey(keyName, "public-key")).rejects.toThrowError(
			GeneralError
		);
	});

	test("can fail to remove a key with no key name", async () => {
		await expect(vaultConnector.removeKey(undefined as unknown as string)).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: {
				property: "name",
				value: "undefined"
			}
		});
	});
	test("can fail to remove a key if it doesn't exist", async () => {
		await expect(vaultConnector.removeKey(TEST_KEY_NAME)).rejects.toMatchObject({
			name: "NotFoundError",
			properties: {
				notFoundId: TEST_KEY_NAME
			}
		});
	});

	test("can backup a key", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(keyName, keyType);

		const backup = await vaultConnector.backupKey(keyName);

		expect(backup).toBeDefined();
		expect(typeof backup).toBe("string");
		expect(backup.length).toBeGreaterThan(0);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can restore a key", async () => {
		const originalKeyName = TEST_RESTORE_KEY_NAME;
		const restoredKeyNewName = TEST_RESTORE_NEW_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(originalKeyName, keyType);
		const backup = await vaultConnector.backupKey(originalKeyName);

		await vaultConnector.restoreKey(restoredKeyNewName, backup);
		const getOriginalKey = await vaultConnector.exportKey(originalKeyName, "public-key");
		const getRestoredKey = await vaultConnector.exportKey(restoredKeyNewName, "public-key");

		expect(getRestoredKey).toBeDefined();
		expect(getOriginalKey.key).toEqual(getRestoredKey.key);

		await cleanupKeys([TEST_RESTORE_KEY_NAME, TEST_RESTORE_NEW_KEY_NAME]);
	});

	test("can rename a key", async () => {
		const originalKeyName = TEST_RESTORE_KEY_NAME;
		const newKeyName = TEST_RESTORE_NEW_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(originalKeyName, keyType);

		await vaultConnector.renameKey(originalKeyName, newKeyName);

		// Verify the original key is removed
		await expect(vaultConnector.exportKey(originalKeyName, "public-key")).rejects.toThrowError(
			GeneralError
		);

		// Verify the renamed key exists
		const renamedKey = await vaultConnector.exportKey(newKeyName, "public-key");

		expect(renamedKey).toBeDefined();
		expect(renamedKey.key.length).toBeGreaterThan(0);

		await cleanupKeys([newKeyName]);
	});

	test("can fail to rename a key with no key name", async () => {
		await expect(
			vaultConnector.renameKey(undefined as unknown as string, undefined as unknown as string)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: {
				property: "name",
				value: "undefined"
			}
		});
	});

	test("can fail to rename a key with no new key name", async () => {
		await expect(
			vaultConnector.renameKey("foo", undefined as unknown as string)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: {
				property: "newName",
				value: "undefined"
			}
		});
	});

	test("can fail to rename a key if it doesn't exist", async () => {
		await expect(vaultConnector.renameKey(TEST_KEY_NAME, "foo")).rejects.toMatchObject({
			name: "GeneralError",
			message: "hashicorpVaultConnector.renameKeyFailed",
			properties: {
				name: TEST_KEY_NAME,
				newName: "foo"
			}
		});
	});

	test("can fail to rename a key if the new name already exists", async () => {
		const originalKeyName = TEST_RESTORE_KEY_NAME;
		const newKeyName = TEST_RESTORE_NEW_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(originalKeyName, keyType);
		await vaultConnector.createKey(newKeyName, keyType);

		await expect(vaultConnector.renameKey(originalKeyName, newKeyName)).rejects.toMatchObject({
			name: "GeneralError",
			message: "hashicorpVaultConnector.renameKeyFailed",
			properties: {
				name: originalKeyName,
				newName: newKeyName
			}
		});

		await cleanupKeys([originalKeyName, newKeyName]);
	});

	test("can get an asymmetric key", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(keyName, keyType);

		const retrievedKey = await vaultConnector.getKey(keyName);

		expect(retrievedKey).toBeDefined();
		expect(retrievedKey.publicKey).toBeDefined();
		expect(retrievedKey.publicKey?.length).toBeGreaterThan(0);
		expect(retrievedKey.privateKey).toBeDefined();
		expect(retrievedKey.privateKey.length).toBeGreaterThan(0);
		expect(retrievedKey.type).toEqual(keyType);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can get a symmetric key", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.ChaCha20Poly1305;

		await vaultConnector.createKey(keyName, keyType);

		const retrievedKey = await vaultConnector.getKey(keyName);

		expect(retrievedKey).toBeDefined();
		expect(retrievedKey.publicKey).toBeUndefined();
		expect(retrievedKey.privateKey).toBeDefined();
		expect(retrievedKey.privateKey.length).toBeGreaterThan(0);
		expect(retrievedKey.type).toEqual(keyType);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can sign data with a key", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(keyName, keyType);

		const dataToSign = new Uint8Array([1, 2, 3, 4, 5]);

		const signature = await vaultConnector.sign(keyName, dataToSign);

		expect(signature).toBeDefined();
		expect(signature.length).toBeGreaterThan(0);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can verify signature with a key", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		const publicKey = await vaultConnector.createKey(keyName, keyType);

		const dataToSign = new Uint8Array([1, 2, 3, 4, 5]);

		const signature = await vaultConnector.sign(keyName, dataToSign);

		const isVerified = await vaultConnector.verify(keyName, dataToSign, signature);

		expect(isVerified).toBe(true);
		expect(Ed25519.verify(publicKey, dataToSign, signature)).toBe(true);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can fail to verify signature with a key", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(keyName, keyType);

		const dataToSign = new Uint8Array([1, 2, 3, 4, 5]);
		const invalidData = new Uint8Array([5, 4, 3, 2, 1]);

		const signature = await vaultConnector.sign(keyName, dataToSign);

		const isVerified = await vaultConnector.verify(keyName, invalidData, signature);

		expect(isVerified).toBe(false);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can sign and verify data", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.Ed25519;

		await vaultConnector.createKey(keyName, keyType);

		const data = Converter.utf8ToBytes("test-data");

		const signature = await vaultConnector.sign(keyName, data);

		const isValid = await vaultConnector.verify(keyName, data, signature);

		expect(isValid).toBe(true);

		await cleanupKeys([TEST_KEY_NAME]);
	});

	test("can fail to sign with a key with no key name", async () => {
		await expect(
			vaultConnector.sign(undefined as unknown as string, undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.string",
			properties: {
				property: "name",
				value: "undefined"
			}
		});
	});
	test("can fail to sign with a key with no data", async () => {
		await expect(
			vaultConnector.sign(TEST_KEY_NAME, undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.uint8Array",
			properties: {
				property: "data",
				value: "undefined"
			}
		});
	});
	test("can fail to sign with a key if it doesn't exist", async () => {
		await expect(vaultConnector.sign(TEST_KEY_NAME, new Uint8Array())).rejects.toMatchObject({
			name: "NotFoundError",
			properties: {
				notFoundId: TEST_KEY_NAME
			}
		});
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
			properties: {
				property: "name",
				value: "undefined"
			}
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
			properties: {
				property: "data",
				value: "undefined"
			}
		});
	});
	test("can fail to verify with a key with no signature", async () => {
		await expect(
			vaultConnector.verify(TEST_KEY_NAME, new Uint8Array(), undefined as unknown as Uint8Array)
		).rejects.toMatchObject({
			name: "GuardError",
			message: "guard.uint8Array",
			properties: {
				property: "signature",
				value: "undefined"
			}
		});
	});
	test("can fail to verify with a key if it doesn't exist", async () => {
		await expect(
			vaultConnector.verify(TEST_KEY_NAME, new Uint8Array(), new Uint8Array())
		).rejects.toMatchObject({
			name: "NotFoundError",
			properties: {
				notFoundId: TEST_KEY_NAME
			}
		});
	});

	test("can encrypt and decrypt data", async () => {
		const keyName = TEST_KEY_NAME;
		const keyType = VaultKeyType.ChaCha20Poly1305;
		const encryptionType = VaultEncryptionType.ChaCha20Poly1305;

		const symmetricKey = await vaultConnector.createKey(keyName, keyType);

		const data = Converter.utf8ToBytes("test-data");

		const encryptedData = await vaultConnector.encrypt(keyName, encryptionType, data);

		expect(encryptedData).toBeDefined();
		expect(encryptedData.length).toBeGreaterThan(0);

		const decryptedData = await vaultConnector.decrypt(keyName, encryptionType, encryptedData);

		expect(decryptedData).toBeDefined();
		expect(decryptedData.length).toBeGreaterThan(0);
		expect(decryptedData).toEqual(data);

		const nonce = encryptedData.slice(0, 12);
		const ciphertext = encryptedData.slice(12);

		const cipher = new ChaCha20Poly1305(symmetricKey, nonce);
		const encrypted = cipher.encrypt(data);
		expect(encrypted).toEqual(ciphertext);
		expect(cipher.decrypt(ciphertext)).toEqual(data);

		await cleanupKeys([TEST_KEY_NAME]);
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
			properties: {
				property: "name",
				value: "undefined"
			}
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
			properties: {
				property: "encryptionType",
				value: "undefined"
			}
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
			properties: {
				property: "data",
				value: "undefined"
			}
		});
	});

	test("can fail to encrypt with a key if it doesn't exist", async () => {
		await expect(
			vaultConnector.encrypt(TEST_KEY_NAME, VaultEncryptionType.ChaCha20Poly1305, new Uint8Array())
		).rejects.toMatchObject({
			name: "NotFoundError",
			properties: {
				notFoundId: TEST_KEY_NAME
			}
		});
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
			properties: {
				property: "name",
				value: "undefined"
			}
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
			properties: {
				property: "encryptionType",
				value: "undefined"
			}
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
			properties: {
				property: "encryptedData",
				value: "undefined"
			}
		});
	});

	test("can fail to decrypt with a key if it doesn't exist", async () => {
		await expect(
			vaultConnector.decrypt(TEST_KEY_NAME, VaultEncryptionType.ChaCha20Poly1305, new Uint8Array())
		).rejects.toMatchObject({
			name: "NotFoundError",
			properties: {
				notFoundId: TEST_KEY_NAME
			}
		});
	});

	test("can perform key operations with a prefix", async () => {
		const vaultConnector2 = new HashicorpVaultConnector({
			config: { ...TEST_VAULT_CONFIG, prefix: "foo" }
		});

		const prefixKey = "key-with-prefix";

		await vaultConnector2.createKey(prefixKey, VaultKeyType.ChaCha20Poly1305);

		const key = await vaultConnector2.getKey(prefixKey);
		expect(key.type).toEqual(2);

		const encrypted = await vaultConnector2.encrypt(
			prefixKey,
			VaultEncryptionType.ChaCha20Poly1305,
			new Uint8Array([1, 2, 3, 4, 5])
		);

		expect(encrypted.length).toEqual(33);

		const decrypted = await vaultConnector2.decrypt(
			prefixKey,
			VaultEncryptionType.ChaCha20Poly1305,
			encrypted
		);
		expect(decrypted).toEqual(new Uint8Array([1, 2, 3, 4, 5]));

		await vaultConnector2.createKey(`${prefixKey}-1`, VaultKeyType.Ed25519);

		const signature = await vaultConnector2.sign(`${prefixKey}-1`, new Uint8Array([1, 2, 3, 4, 5]));
		expect(signature).toBeDefined();

		const verified = await vaultConnector2.verify(
			`${prefixKey}-1`,
			new Uint8Array([1, 2, 3, 4, 5]),
			signature
		);
		expect(verified).toEqual(true);

		await vaultConnector2.removeKey(`${prefixKey}-1`);

		await vaultConnector2.removeKey(prefixKey);
	});

	test("can perform secret operations with a prefix", async () => {
		const vaultConnector2 = new HashicorpVaultConnector({
			config: { ...TEST_VAULT_CONFIG, prefix: "foo" }
		});

		const prefixSecret = "secret-with-prefix";

		await vaultConnector2.setSecret(prefixSecret, { foo: "bar" });

		const secret = await vaultConnector2.getSecret(prefixSecret);

		expect(secret).toEqual({ foo: "bar" });

		await vaultConnector2.removeSecret(prefixSecret);
	});
});
