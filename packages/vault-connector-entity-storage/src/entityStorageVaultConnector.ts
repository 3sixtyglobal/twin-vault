// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import {
	AlreadyExistsError,
	Converter,
	GeneralError,
	Guards,
	Is,
	NotFoundError,
	RandomHelper
} from "@twin.org/core";
import { Bip39, ChaCha20Poly1305, Ed25519 } from "@twin.org/crypto";
import {
	EntityStorageConnectorFactory,
	type IEntityStorageConnector
} from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import { type IVaultConnector, VaultEncryptionType, VaultKeyType } from "@twin.org/vault-models";
import type { VaultKey } from "./entities/vaultKey.js";
import type { VaultSecret } from "./entities/vaultSecret.js";
import type { IEntityStorageVaultConnectorConstructorOptions } from "./models/IEntityStorageVaultConnectorConstructorOptions.js";

/**
 * Class for performing vault operations in entity storage.
 */
export class EntityStorageVaultConnector implements IVaultConnector {
	/**
	 * The namespace supported by the vault connector.
	 */
	public static readonly NAMESPACE: string = "entity-storage";

	/**
	 * Runtime name for the class.
	 */
	public static readonly CLASS_NAME: string = nameof<EntityStorageVaultConnector>();

	/**
	 * The entity storage for the vault keys.
	 * @internal
	 */
	private readonly _vaultKeyEntityStorageConnector: IEntityStorageConnector<VaultKey>;

	/**
	 * The entity storage for the vault secrets.
	 * @internal
	 */
	private readonly _vaultSecretEntityStorageConnector: IEntityStorageConnector<VaultSecret>;

	/**
	 * A prefix for the keys stored in the vault.
	 * @internal
	 */
	private readonly _prefix?: string;

	/**
	 * Create a new instance of EntityStorageVaultConnector.
	 * @param options The options for the connector.
	 */
	constructor(options?: IEntityStorageVaultConnectorConstructorOptions) {
		this._vaultKeyEntityStorageConnector = EntityStorageConnectorFactory.get(
			options?.vaultKeyEntityStorageType ?? "vault-key"
		);
		this._vaultSecretEntityStorageConnector = EntityStorageConnectorFactory.get(
			options?.vaultSecretEntityStorageType ?? "vault-secret"
		);
		this._prefix = options?.config?.prefix;
	}

	/**
	 * Returns the class name of the component.
	 * @returns The class name of the component.
	 */
	public className(): string {
		return EntityStorageVaultConnector.CLASS_NAME;
	}

	/**
	 * Generate a new key and store it in the vault.
	 * @param name The name of the key to generate and store in the vault.
	 * @param type The type of key to create.
	 * @returns The public key for the key pair.
	 */
	public async createKey(name: string, type: VaultKeyType): Promise<Uint8Array> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultKeyType>(
			EntityStorageVaultConnector.CLASS_NAME,
			nameof(type),
			type,
			Object.values(VaultKeyType)
		);

		const fullKeyName = this.createKeyName(name);

		const existingVaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (!Is.empty(existingVaultKey)) {
			throw new AlreadyExistsError(
				EntityStorageVaultConnector.CLASS_NAME,
				"keyAlreadyExists",
				name
			);
		}

		const mnemonic = Bip39.randomMnemonic();
		const seed = Bip39.mnemonicToSeed(mnemonic);

		let privateKey: Uint8Array;
		let publicKey: Uint8Array | undefined;

		if (type === VaultKeyType.Ed25519) {
			privateKey = seed.slice(0, Ed25519.PRIVATE_KEY_SIZE);
			publicKey = Ed25519.publicKeyFromPrivateKey(privateKey);
		} else {
			// ChaCha20Poly1305 is symmetric, so the private key is the same as the public key.
			privateKey = seed.slice(0, 32);
		}

		const now = new Date(Date.now()).toISOString();
		const vaultKey: VaultKey = {
			id: fullKeyName,
			type,
			privateKey: Converter.bytesToBase64(privateKey),
			publicKey: Is.undefined(publicKey) ? undefined : Converter.bytesToBase64(publicKey),
			dateCreated: now,
			dateModified: now
		};

		await this._vaultKeyEntityStorageConnector.set(vaultKey);

		return publicKey ?? privateKey;
	}

	/**
	 * Add an existing key to the vault.
	 * @param name The name of the key to add to the vault.
	 * @param type The type of key to add.
	 * @param privateKey The private key.
	 * @param publicKey The public key, can be undefined if the key type is symmetric.
	 * @returns A promise that resolves when the key has been stored.
	 */
	public async addKey(
		name: string,
		type: VaultKeyType,
		privateKey: Uint8Array,
		publicKey?: Uint8Array
	): Promise<void> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultKeyType>(
			EntityStorageVaultConnector.CLASS_NAME,
			nameof(type),
			type,
			Object.values(VaultKeyType)
		);
		Guards.uint8Array(EntityStorageVaultConnector.CLASS_NAME, nameof(privateKey), privateKey);
		if (type !== VaultKeyType.ChaCha20Poly1305) {
			Guards.uint8Array(EntityStorageVaultConnector.CLASS_NAME, nameof(publicKey), publicKey);
		}

		const fullKeyName = this.createKeyName(name);

		const existingVaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (!Is.empty(existingVaultKey)) {
			throw new AlreadyExistsError(
				EntityStorageVaultConnector.CLASS_NAME,
				"keyAlreadyExists",
				name
			);
		}

		const now = new Date(Date.now()).toISOString();
		const vaultKey: VaultKey = {
			id: fullKeyName,
			type,
			privateKey: Converter.bytesToBase64(privateKey),
			publicKey: Is.undefined(publicKey) ? undefined : Converter.bytesToBase64(publicKey),
			dateCreated: now,
			dateModified: now
		};

		await this._vaultKeyEntityStorageConnector.set(vaultKey);
	}

	/**
	 * Get a key from the vault.
	 * @param name The name of the key to get from the vault.
	 * @param components Which key components to return, defaults to "both".
	 * @returns The key, publicKey can be undefined if key is symmetric, privateKey can be undefined if only public was requested.
	 * @throws GeneralError if "private" is requested for a symmetric key.
	 */
	public async getKey(
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
	}> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);

		components ??= "both";

		Guards.arrayOneOf<"public" | "private" | "both">(
			EntityStorageVaultConnector.CLASS_NAME,
			nameof(components),
			components,
			["public", "private", "both"]
		);

		const fullKeyName = this.createKeyName(name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "keyNotFound", name);
		}

		if (components === "private" && vaultKey.type === VaultKeyType.ChaCha20Poly1305) {
			throw new GeneralError(
				EntityStorageVaultConnector.CLASS_NAME,
				"symmetricKeyHasNoPrivateKey",
				{
					name
				}
			);
		}

		return {
			type: vaultKey.type,
			privateKey:
				components !== "public" ? Converter.base64ToBytes(vaultKey.privateKey) : undefined,
			publicKey:
				components !== "private" && !Is.undefined(vaultKey.publicKey)
					? Converter.base64ToBytes(vaultKey.publicKey)
					: undefined
		};
	}

	/**
	 * Check if a key exists in the vault.
	 * @param name The name of the key to check.
	 * @returns True if the key exists, false otherwise.
	 */
	public async keyExists(name: string): Promise<boolean> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);

		const fullKeyName = this.createKeyName(name);
		const vaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		return !Is.empty(vaultKey);
	}

	/**
	 * Get the type of a key from the vault without retrieving the key material.
	 * @param name The name of the key.
	 * @returns The key type.
	 * @throws NotFoundError if the key does not exist.
	 */
	public async getKeyType(name: string): Promise<VaultKeyType> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);

		const fullKeyName = this.createKeyName(name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "keyNotFound", name);
		}

		return vaultKey.type;
	}

	/**
	 * Rename a key in the vault.
	 * @param name The name of the key to rename.
	 * @param newName The new name of the key.
	 * @returns A promise that resolves when the key has been renamed.
	 */
	public async renameKey(name: string, newName: string): Promise<void> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(newName), newName);

		const fullKeyName = this.createKeyName(name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "keyNotFound", name);
		}

		const newFullKeyName = this.createKeyName(newName);

		if (fullKeyName !== newFullKeyName) {
			const existingVaultKey = await this._vaultKeyEntityStorageConnector.get(newFullKeyName);
			if (!Is.empty(existingVaultKey)) {
				throw new AlreadyExistsError(
					EntityStorageVaultConnector.CLASS_NAME,
					"keyAlreadyExists",
					newName
				);
			}

			vaultKey.id = newFullKeyName;
			vaultKey.dateModified = new Date(Date.now()).toISOString();

			await this._vaultKeyEntityStorageConnector.set(vaultKey);

			await this._vaultKeyEntityStorageConnector.remove(fullKeyName);
		}
	}

	/**
	 * Remove a key from the vault.
	 * @param name The name of the key to remove from the vault.
	 * @returns A promise that resolves when the key has been removed.
	 */
	public async removeKey(name: string): Promise<void> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);

		const fullKeyName = this.createKeyName(name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "keyNotFound", name);
		}

		await this._vaultKeyEntityStorageConnector.remove(fullKeyName);
	}

	/**
	 * Sign the data using a key in the vault.
	 * @param name The name of the key to use for signing.
	 * @param data The data to sign.
	 * @returns The signature for the data.
	 */
	public async sign(name: string, data: Uint8Array): Promise<Uint8Array> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.uint8Array(EntityStorageVaultConnector.CLASS_NAME, nameof(data), data);

		const fullKeyName = this.createKeyName(name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "keyNotFound", name);
		}

		let signatureBytes;
		const privateKeyBytes = Converter.base64ToBytes(vaultKey.privateKey);
		if (vaultKey.type === VaultKeyType.Ed25519) {
			signatureBytes = Ed25519.sign(privateKeyBytes, data);
		} else {
			throw new GeneralError(EntityStorageVaultConnector.CLASS_NAME, "unsupportedKeyType", {
				keyType: vaultKey.type
			});
		}

		return signatureBytes;
	}

	/**
	 * Verify the signature of the data using a key in the vault.
	 * @param name The name of the key to use for verification.
	 * @param data The data that was signed.
	 * @param signature The signature to verify.
	 * @returns True if the verification is successful.
	 */
	public async verify(name: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.uint8Array(EntityStorageVaultConnector.CLASS_NAME, nameof(data), data);
		Guards.uint8Array(EntityStorageVaultConnector.CLASS_NAME, nameof(signature), signature);

		const fullKeyName = this.createKeyName(name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "keyNotFound", name);
		}

		if (vaultKey.type === VaultKeyType.Ed25519) {
			const publicKeyBytes = Converter.base64ToBytes(vaultKey.publicKey ?? "");
			return Ed25519.verify(publicKeyBytes, data, signature);
		}

		throw new GeneralError(EntityStorageVaultConnector.CLASS_NAME, "unsupportedKeyType", {
			keyType: vaultKey.type
		});
	}

	/**
	 * Encrypt the data using a key in the vault.
	 * @param name The name of the key to use for encryption.
	 * @param encryptionType The type of encryption to use.
	 * @param data The data to encrypt.
	 * @returns The encrypted data.
	 */
	public async encrypt(
		name: string,
		encryptionType: VaultEncryptionType,
		data: Uint8Array
	): Promise<Uint8Array> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultEncryptionType>(
			EntityStorageVaultConnector.CLASS_NAME,
			nameof(encryptionType),
			encryptionType,
			Object.values(VaultEncryptionType)
		);
		Guards.uint8Array(EntityStorageVaultConnector.CLASS_NAME, nameof(data), data);

		const fullKeyName = this.createKeyName(name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "keyNotFound", name);
		}

		if (
			encryptionType === VaultEncryptionType.ChaCha20Poly1305 &&
			vaultKey.type !== VaultKeyType.ChaCha20Poly1305
		) {
			throw new GeneralError(EntityStorageVaultConnector.CLASS_NAME, "keyTypeMismatch", {
				encryptionType,
				keyType: vaultKey.type
			});
		}

		const privateKey = Converter.base64ToBytes(vaultKey.privateKey);

		const nonce = RandomHelper.generate(12);

		const cipher = new ChaCha20Poly1305(privateKey, nonce);
		const payload = cipher.encrypt(data);

		const encryptedBytes = new Uint8Array(nonce.length + payload.length);
		encryptedBytes.set(nonce);
		encryptedBytes.set(payload, nonce.length);

		return encryptedBytes;
	}

	/**
	 * Decrypt the data using a key in the vault.
	 * @param name The name of the key to use for decryption.
	 * @param encryptionType The type of encryption to use.
	 * @param encryptedData The data to decrypt.
	 * @returns The decrypted data.
	 */
	public async decrypt(
		name: string,
		encryptionType: VaultEncryptionType,
		encryptedData: Uint8Array
	): Promise<Uint8Array> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultEncryptionType>(
			EntityStorageVaultConnector.CLASS_NAME,
			nameof(encryptionType),
			encryptionType,
			Object.values(VaultEncryptionType)
		);
		Guards.uint8Array(EntityStorageVaultConnector.CLASS_NAME, nameof(encryptedData), encryptedData);

		const fullKeyName = this.createKeyName(name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(fullKeyName);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "keyNotFound", name);
		}

		if (
			encryptionType === VaultEncryptionType.ChaCha20Poly1305 &&
			vaultKey.type !== VaultKeyType.ChaCha20Poly1305
		) {
			throw new GeneralError(EntityStorageVaultConnector.CLASS_NAME, "keyTypeMismatch", {
				encryptionType,
				keyType: vaultKey.type
			});
		}

		const privateKey = Converter.base64ToBytes(vaultKey.privateKey);

		const nonce = encryptedData.slice(0, 12);

		const cipher = new ChaCha20Poly1305(privateKey, nonce);
		const decryptedBytes = cipher.decrypt(encryptedData.slice(nonce.length));

		return decryptedBytes;
	}

	/**
	 * Store a secret in the vault.
	 * @param name The name of the item in the vault to set.
	 * @param data The item to add to the vault.
	 * @returns A promise that resolves when the secret has been stored.
	 */
	public async setSecret<T>(name: string, data: T): Promise<void> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.defined(EntityStorageVaultConnector.CLASS_NAME, nameof(data), data);

		const fullKeyName = this.createKeyName(name);

		const existingSecret = await this._vaultSecretEntityStorageConnector.get(fullKeyName);
		const now = new Date(Date.now()).toISOString();

		const vaultSecret: VaultSecret = {
			id: fullKeyName,
			data,
			dateCreated: existingSecret?.dateCreated ?? now,
			dateModified: now
		};

		await this._vaultSecretEntityStorageConnector.set(vaultSecret);
	}

	/**
	 * Get a secret from the vault.
	 * @param name The name of the item in the vault to get.
	 * @returns The item from the vault.
	 * @throws Error if the item is not found.
	 */
	public async getSecret<T>(name: string): Promise<T> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);

		const fullKeyName = this.createKeyName(name);

		const secret = await this._vaultSecretEntityStorageConnector.get(fullKeyName);

		if (Is.empty(secret)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "secretNotFound", name);
		}

		return secret.data as T;
	}

	/**
	 * Check if a secret exists in the vault.
	 * @param name The name of the secret to check.
	 * @returns True if the secret exists, false otherwise.
	 */
	public async secretExists(name: string): Promise<boolean> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);

		const fullKeyName = this.createKeyName(name);
		const secret = await this._vaultSecretEntityStorageConnector.get(fullKeyName);
		return !Is.empty(secret);
	}

	/**
	 * Remove a secret from the vault.
	 * @param name The name of the item in the vault to remove.
	 * @returns A promise that resolves when the secret has been removed.
	 * @throws Error if the item is not found.
	 */
	public async removeSecret(name: string): Promise<void> {
		Guards.stringValue(EntityStorageVaultConnector.CLASS_NAME, nameof(name), name);

		const fullKeyName = this.createKeyName(name);

		const secret = await this._vaultSecretEntityStorageConnector.get(fullKeyName);

		if (Is.empty(secret)) {
			throw new NotFoundError(EntityStorageVaultConnector.CLASS_NAME, "secretNotFound", name);
		}

		return this._vaultSecretEntityStorageConnector.remove(fullKeyName);
	}

	/**
	 * Create the key name with prefix if defined.
	 * @param name The base name of the key.
	 * @returns The key name with prefix if defined.
	 * @internal
	 */
	private createKeyName(name: string): string {
		return Is.stringValue(this._prefix) ? `${this._prefix}-${name}` : name;
	}
}
