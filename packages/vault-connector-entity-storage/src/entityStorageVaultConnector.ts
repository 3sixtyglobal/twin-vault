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
import { Bip39, ChaCha20Poly1305, Ed25519, Secp256k1 } from "@twin.org/crypto";
import {
	EntityStorageConnectorFactory,
	type IEntityStorageConnector
} from "@twin.org/entity-storage-models";
import { nameof } from "@twin.org/nameof";
import { type IVaultConnector, VaultEncryptionType, VaultKeyType } from "@twin.org/vault-models";
import type { VaultKey } from "./entities/vaultKey";
import type { VaultSecret } from "./entities/vaultSecret";
import type { IEntityStorageVaultConnectorConstructorOptions } from "./models/IEntityStorageVaultConnectorConstructorOptions";

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
	public readonly CLASS_NAME: string = nameof<EntityStorageVaultConnector>();

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
	}

	/**
	 * Generate a new key and store it in the vault.
	 * @param name The name of the key to generate and store in the vault.
	 * @param type The type of key to create.
	 * @returns The public key for the key pair.
	 */
	public async createKey(name: string, type: VaultKeyType): Promise<Uint8Array> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultKeyType>(
			this.CLASS_NAME,
			nameof(type),
			type,
			Object.values(VaultKeyType)
		);

		const existingVaultKey = await this._vaultKeyEntityStorageConnector.get(name);
		if (!Is.empty(existingVaultKey)) {
			throw new AlreadyExistsError(this.CLASS_NAME, "keyAlreadyExists", name);
		}

		const mnemonic = Bip39.randomMnemonic();
		const seed = Bip39.mnemonicToSeed(mnemonic);

		let privateKey: Uint8Array;
		let publicKey: Uint8Array | undefined;

		if (type === VaultKeyType.Ed25519) {
			privateKey = seed.slice(0, Ed25519.PRIVATE_KEY_SIZE);
			publicKey = Ed25519.publicKeyFromPrivateKey(privateKey);
		} else if (type === VaultKeyType.Secp256k1) {
			privateKey = seed.slice(0, Secp256k1.PRIVATE_KEY_SIZE);
			publicKey = Secp256k1.publicKeyFromPrivateKey(privateKey);
		} else {
			// ChaCha20Poly1305 is symmetric, so the private key is the same as the public key.
			privateKey = seed.slice(0, 32);
		}

		const vaultKey: VaultKey = {
			id: name,
			type,
			privateKey: Converter.bytesToBase64(privateKey),
			publicKey: Is.undefined(publicKey) ? undefined : Converter.bytesToBase64(publicKey)
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
	 * @returns Nothing.
	 */
	public async addKey(
		name: string,
		type: VaultKeyType,
		privateKey: Uint8Array,
		publicKey?: Uint8Array
	): Promise<void> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultKeyType>(
			this.CLASS_NAME,
			nameof(type),
			type,
			Object.values(VaultKeyType)
		);
		Guards.uint8Array(this.CLASS_NAME, nameof(privateKey), privateKey);
		if (type !== VaultKeyType.ChaCha20Poly1305) {
			Guards.uint8Array(this.CLASS_NAME, nameof(publicKey), publicKey);
		}

		const existingVaultKey = await this._vaultKeyEntityStorageConnector.get(name);
		if (!Is.empty(existingVaultKey)) {
			throw new AlreadyExistsError(this.CLASS_NAME, "keyAlreadyExists", name);
		}

		const vaultKey: VaultKey = {
			id: name,
			type,
			privateKey: Converter.bytesToBase64(privateKey),
			publicKey: Is.undefined(publicKey) ? undefined : Converter.bytesToBase64(publicKey)
		};

		await this._vaultKeyEntityStorageConnector.set(vaultKey);
	}

	/**
	 * Get a key from the vault.
	 * @param name The name of the key to get from the vault.
	 * @returns The key, publicKey can be undefined if key is symmetric.
	 */
	public async getKey(name: string): Promise<{
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
	}> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(name);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(this.CLASS_NAME, "keyNotFound", name);
		}

		return {
			type: vaultKey.type,
			privateKey: Converter.base64ToBytes(vaultKey.privateKey),
			publicKey: Is.undefined(vaultKey.publicKey)
				? undefined
				: Converter.base64ToBytes(vaultKey.publicKey)
		};
	}

	/**
	 * Rename a key in the vault.
	 * @param name The name of the key to rename.
	 * @param newName The new name of the key.
	 * @returns Nothing.
	 */
	public async renameKey(name: string, newName: string): Promise<void> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);
		Guards.stringValue(this.CLASS_NAME, nameof(newName), newName);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(name);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(this.CLASS_NAME, "keyNotFound", name);
		}

		await this._vaultKeyEntityStorageConnector.remove(name);

		vaultKey.id = newName;

		await this._vaultKeyEntityStorageConnector.set(vaultKey);
	}

	/**
	 * Remove a key from the vault.
	 * @param name The name of the key to create in the value.
	 * @returns Nothing.
	 */
	public async removeKey(name: string): Promise<void> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(name);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(this.CLASS_NAME, "keyNotFound", name);
		}

		await this._vaultKeyEntityStorageConnector.remove(name);
	}

	/**
	 * Sign the data using a key in the vault.
	 * @param name The name of the key to use for signing.
	 * @param data The data to sign.
	 * @returns The signature for the data.
	 */
	public async sign(name: string, data: Uint8Array): Promise<Uint8Array> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);
		Guards.uint8Array(this.CLASS_NAME, nameof(data), data);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(name);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(this.CLASS_NAME, "keyNotFound", name);
		}

		let signatureBytes;
		const privateKeyBytes = Converter.base64ToBytes(vaultKey.privateKey);
		if (vaultKey.type === VaultKeyType.Ed25519) {
			signatureBytes = Ed25519.sign(privateKeyBytes, data);
		} else if (vaultKey.type === VaultKeyType.Secp256k1) {
			signatureBytes = Secp256k1.sign(privateKeyBytes, data);
		} else {
			throw new GeneralError(this.CLASS_NAME, "unsupportedKeyType", { keyType: vaultKey.type });
		}

		return signatureBytes;
	}

	/**
	 * Verify the signature of the data using a key in the vault.
	 * @param name The name of the key to use for verification.
	 * @param data The data that was signed in base64.
	 * @param signature The signature to verify in base64.
	 * @returns True if the verification is successful.
	 */
	public async verify(name: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);
		Guards.uint8Array(this.CLASS_NAME, nameof(data), data);
		Guards.uint8Array(this.CLASS_NAME, nameof(signature), signature);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(name);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(this.CLASS_NAME, "keyNotFound", name);
		}

		if (vaultKey.type === VaultKeyType.Ed25519) {
			const publicKeyBytes = Converter.base64ToBytes(vaultKey.publicKey ?? "");
			return Ed25519.verify(publicKeyBytes, data, signature);
		} else if (vaultKey.type === VaultKeyType.Secp256k1) {
			const publicKeyBytes = Converter.base64ToBytes(vaultKey.publicKey ?? "");
			return Secp256k1.verify(publicKeyBytes, data, signature);
		}

		throw new GeneralError(this.CLASS_NAME, "unsupportedKeyType", { keyType: vaultKey.type });
	}

	/**
	 * Encrypt the data using a key in the vault.
	 * @param name The name of the key to use for encryption.
	 * @param encryptionType The type of encryption to use.
	 * @param data The data to encrypt in base64.
	 * @returns The encrypted data in base64.
	 */
	public async encrypt(
		name: string,
		encryptionType: VaultEncryptionType,
		data: Uint8Array
	): Promise<Uint8Array> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultEncryptionType>(
			this.CLASS_NAME,
			nameof(encryptionType),
			encryptionType,
			Object.values(VaultEncryptionType)
		);
		Guards.uint8Array(this.CLASS_NAME, nameof(data), data);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(name);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(this.CLASS_NAME, "keyNotFound", name);
		}

		if (
			encryptionType === VaultEncryptionType.ChaCha20Poly1305 &&
			vaultKey.type !== VaultKeyType.ChaCha20Poly1305
		) {
			throw new GeneralError(this.CLASS_NAME, "keyTypeMismatch", {
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
	 * @param encryptedData The data to decrypt in base64.
	 * @returns The decrypted data in base64.
	 */
	public async decrypt(
		name: string,
		encryptionType: VaultEncryptionType,
		encryptedData: Uint8Array
	): Promise<Uint8Array> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultEncryptionType>(
			this.CLASS_NAME,
			nameof(encryptionType),
			encryptionType,
			Object.values(VaultEncryptionType)
		);
		Guards.uint8Array(this.CLASS_NAME, nameof(encryptedData), encryptedData);

		const vaultKey = await this._vaultKeyEntityStorageConnector.get(name);
		if (Is.empty(vaultKey)) {
			throw new NotFoundError(this.CLASS_NAME, "keyNotFound", name);
		}

		if (
			encryptionType === VaultEncryptionType.ChaCha20Poly1305 &&
			vaultKey.type !== VaultKeyType.ChaCha20Poly1305
		) {
			throw new GeneralError(this.CLASS_NAME, "keyTypeMismatch", {
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
	 * @param item The item to add to the vault.
	 * @returns Nothing.
	 */
	public async setSecret<T>(name: string, item: T): Promise<void> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);
		Guards.defined(this.CLASS_NAME, nameof(item), item);

		const vaultSecret: VaultSecret = {
			id: name,
			data: item
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
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);

		const secret = await this._vaultSecretEntityStorageConnector.get(name);

		if (Is.empty(secret)) {
			throw new NotFoundError(this.CLASS_NAME, "secretNotFound", name);
		}

		return secret.data as T;
	}

	/**
	 * Remove a secret from the vault.
	 * @param name The name of the item in the vault to remove.
	 * @returns Nothing.
	 * @throws Error if the item is not found.
	 */
	public async removeSecret(name: string): Promise<void> {
		Guards.stringValue(this.CLASS_NAME, nameof(name), name);

		const secret = await this._vaultSecretEntityStorageConnector.get(name);

		if (Is.empty(secret)) {
			throw new NotFoundError(this.CLASS_NAME, "secretNotFound", name);
		}

		return this._vaultSecretEntityStorageConnector.remove(name);
	}
}
