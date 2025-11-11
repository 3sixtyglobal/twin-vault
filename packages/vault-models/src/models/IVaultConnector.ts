// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IComponent } from "@twin.org/core";
import type { VaultEncryptionType } from "./vaultEncryptionType.js";
import type { VaultKeyType } from "./vaultKeyType.js";

/**
 * Interface describing a vault securely storing data.
 */
export interface IVaultConnector extends IComponent {
	/**
	 * Generate a new key and store it in the vault.
	 * @param name The name of the key to generate and store in the vault.
	 * @param type The type of key to create.
	 * @returns The public key for the key pair.
	 */
	createKey(name: string, type: VaultKeyType): Promise<Uint8Array>;

	/**
	 * Add an existing key to the vault.
	 * @param name The name of the key to add to the vault.
	 * @param type The type of key to add.
	 * @param privateKey The private key.
	 * @param publicKey The public key, can be undefined if the key type is symmetric.
	 * @returns Nothing.
	 */
	addKey(
		name: string,
		type: VaultKeyType,
		privateKey: Uint8Array,
		publicKey?: Uint8Array
	): Promise<void>;

	/**
	 * Get a key from the vault.
	 * @param name The name of the key to get from the vault.
	 * @returns The key, publicKey can be undefined if key is symmetric.
	 */
	getKey(name: string): Promise<{
		/**
		 * The type of the key e.g. Ed25519, Secp256k1.
		 */
		type: VaultKeyType;

		/**
		 * The private key.
		 */
		privateKey: Uint8Array;

		/**
		 * The public key, which can be undefined if key type is symmetric.
		 */
		publicKey?: Uint8Array;
	}>;

	/**
	 * Rename a key in the vault.
	 * @param name The name of the key to rename.
	 * @param newName The new name of the key.
	 * @returns Nothing.
	 */
	renameKey(name: string, newName: string): Promise<void>;

	/**
	 * Remove a key from the vault.
	 * @param name The name of the key to remove from the vault.
	 * @returns Nothing.
	 */
	removeKey(name: string): Promise<void>;

	/**
	 * Sign the data using a key in the vault.
	 * @param name The name of the key to use for signing.
	 * @param data The data to sign.
	 * @returns The signature for the data.
	 */
	sign(name: string, data: Uint8Array): Promise<Uint8Array>;

	/**
	 * Verify the signature of the data using a key in the vault.
	 * @param name The name of the key to use for verification.
	 * @param data The data that was signed.
	 * @param signature The signature to verify.
	 * @returns True if the verification is successful.
	 */
	verify(name: string, data: Uint8Array, signature: Uint8Array): Promise<boolean>;

	/**
	 * Encrypt the data using a key in the vault.
	 * @param name The name of the key to use for encryption.
	 * @param encryptionType The type of encryption to use.
	 * @param data The data to encrypt.
	 * @returns The encrypted data.
	 */
	encrypt(name: string, encryptionType: VaultEncryptionType, data: Uint8Array): Promise<Uint8Array>;

	/**
	 * Decrypt the data using a key in the vault.
	 * @param name The name of the key to use for decryption.
	 * @param encryptionType The type of encryption to use.
	 * @param encryptedData The data to decrypt.
	 * @returns The decrypted data.
	 */
	decrypt(
		name: string,
		encryptionType: VaultEncryptionType,
		encryptedData: Uint8Array
	): Promise<Uint8Array>;

	/**
	 * Store a secret in the vault.
	 * @param name The name of the secret in the vault to set.
	 * @param data The secret to add to the vault.
	 * @returns Nothing.
	 */
	setSecret<T>(name: string, data: T): Promise<void>;

	/**
	 * Get a secret from the vault.
	 * @param name The name of the secret in the vault to get.
	 * @returns The secret from the vault.
	 * @throws Error if the secret is not found.
	 */
	getSecret<T>(name: string): Promise<T>;

	/**
	 * Remove a secret from the vault.
	 * @param name The name of the secret in the vault to remove.
	 * @returns Nothing.
	 * @throws Error if the secret is not found.
	 */
	removeSecret(name: string): Promise<void>;
}
