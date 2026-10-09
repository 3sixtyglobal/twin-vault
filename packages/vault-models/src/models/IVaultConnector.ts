// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IComponent } from "@3sixty/core";
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
	 * @returns A promise that resolves when the key has been stored.
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
	 * @param components Which key components to return, defaults to "both".
	 * @returns The key, publicKey can be undefined if key is symmetric, privateKey can be undefined if only public was requested.
	 * @throws GeneralError if "private" is requested for a symmetric key.
	 */
	getKey(
		name: string,
		components?: "public" | "private" | "both"
	): Promise<{
		/**
		 * The type of the key e.g. Ed25519.
		 */
		type: VaultKeyType;

		/**
		 * The private key, undefined if only public component was requested.
		 */
		privateKey?: Uint8Array;

		/**
		 * The public key, which can be undefined if key type is symmetric or only private was requested.
		 */
		publicKey?: Uint8Array;
	}>;

	/**
	 * Check if a key exists in the vault.
	 * @param name The name of the key to check.
	 * @returns True if the key exists, false otherwise.
	 */
	keyExists(name: string): Promise<boolean>;

	/**
	 * Get the type of a key from the vault without retrieving the key material.
	 * @param name The name of the key.
	 * @returns The key type.
	 * @throws NotFoundError if the key does not exist.
	 */
	getKeyType(name: string): Promise<VaultKeyType>;

	/**
	 * Rename a key in the vault.
	 * @param name The name of the key to rename.
	 * @param newName The new name of the key.
	 * @returns A promise that resolves when the key has been renamed.
	 */
	renameKey(name: string, newName: string): Promise<void>;

	/**
	 * Remove a key from the vault.
	 * @param name The name of the key to remove from the vault.
	 * @returns A promise that resolves when the key has been removed.
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
	 * @returns A promise that resolves when the secret has been stored.
	 */
	setSecret<T>(name: string, data: T): Promise<void>;

	/**
	 * Check if a secret exists in the vault.
	 * @param name The name of the secret to check.
	 * @returns True if the secret exists, false otherwise.
	 */
	secretExists(name: string): Promise<boolean>;

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
	 * @returns A promise that resolves when the secret has been removed.
	 * @throws Error if the secret is not found.
	 */
	removeSecret(name: string): Promise<void>;
}
