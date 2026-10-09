// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import {
	HealthCategory,
	HealthStatus,
	type IHealth,
	type IHealthProviderComponent
} from "@3sixty/api-models";
import {
	AlreadyExistsError,
	BaseError,
	ComponentFactory,
	Converter,
	GeneralError,
	Guards,
	Is,
	LruCache,
	NotFoundError,
	RandomHelper,
	StringHelper
} from "@3sixty/core";
import { ChaCha20Poly1305, Ed25519 } from "@3sixty/crypto";
import type { ILoggingComponent } from "@3sixty/logging-models";
import { nameof } from "@3sixty/nameof";
import { type IVaultConnector, VaultEncryptionType, VaultKeyType } from "@3sixty/vault-models";
import { FetchHelper, HttpMethod, type IHttpHeaders } from "@3sixty/web";
import type { IBackupKeyResponse } from "./models/IBackupKeyResponse.js";
import type { ICreateKeyRequest } from "./models/ICreateKeyRequest.js";
import type { IDataKeyEnvelope } from "./models/IDataKeyEnvelope.js";
import type { IDecryptDataRequest } from "./models/IDecryptDataRequest.js";
import type { IDecryptDataResponse } from "./models/IDecryptDataResponse.js";
import type { IEncryptDataRequest } from "./models/IEncryptDataRequest.js";
import type { IEncryptDataResponse } from "./models/IEncryptDataResponse.js";
import type { IExportKeyResponse } from "./models/IExportKeyResponse.js";
import type { IHashicorpVaultConnectorConfig } from "./models/IHashicorpVaultConnectorConfig.js";
import type { IHashicorpVaultConnectorConstructorOptions } from "./models/IHashicorpVaultConnectorConstructorOptions.js";
import type { IHashicorpVaultRequest } from "./models/IHashicorpVaultRequest.js";
import type { IHashicorpVaultResponse } from "./models/IHashicorpVaultResponse.js";
import type { IImportKeyRequest } from "./models/IImportKeyRequest.js";
import type { IKeyDeleteConfigResponse } from "./models/IKeyDeleteConfigResponse.js";
import type { IReadKeyResponse } from "./models/IReadKeyResponse.js";
import type { IRestoreKeyRequest } from "./models/IRestoreKeyRequest.js";
import type { ISecretData } from "./models/ISecretData.js";
import type { ISecretVersionResponse } from "./models/ISecretVersionResponse.js";
import type { ISignDataRequest } from "./models/ISignDataRequest.js";
import type { ISignDataResponse } from "./models/ISignDataResponse.js";
import type { IUpdateKeyConfigRequest } from "./models/IUpdateKeyConfigRequest.js";
import type { IVerifyDataRequest } from "./models/IVerifyDataRequest.js";
import type { IVerifyDataResponse } from "./models/IVerifyDataResponse.js";

/**
 * Class for performing vault operations using HashiCorp Vault.
 */
export class HashicorpVaultConnector implements IVaultConnector, IHealthProviderComponent {
	/**
	 * Runtime name for the class.
	 */
	public static readonly CLASS_NAME: string = nameof<HashicorpVaultConnector>();

	/**
	 * The namespace supported by the vault connector.
	 */
	public static readonly NAMESPACE: string = "hashicorp";

	/**
	 * The prefix to strip from keys and encrypted data.
	 * @internal
	 */
	private static readonly _DATA_PREFIX: string = "vault:v1:";

	/**
	 * The prefix marking data encrypted under a wrapped data key.
	 * @internal
	 */
	private static readonly _ENVELOPE_PREFIX: Uint8Array = Converter.utf8ToBytes("twin:env:v1:");

	/**
	 * The length in bytes of a data key.
	 * @internal
	 */
	private static readonly _DATA_KEY_LENGTH: number = 32;

	/**
	 * The length in bytes of a ChaCha20Poly1305 nonce.
	 * @internal
	 */
	private static readonly _NONCE_LENGTH: number = 12;

	/**
	 * The length in bytes of a ChaCha20Poly1305 authentication tag.
	 * @internal
	 */
	private static readonly _TAG_LENGTH: number = 16;

	/**
	 * The default TTL in milliseconds for cached key metadata.
	 * @internal
	 */
	private static readonly _DEFAULT_KEY_METADATA_CACHE_TTL_MS: number = 30000;

	/**
	 * The configuration for the vault connector.
	 * @internal
	 */
	private readonly _config: IHashicorpVaultConnectorConfig;

	/**
	 * The KV mount path.
	 * @internal
	 */
	private readonly _kvMountPath: string;

	/**
	 * The transit mount path.
	 * @internal
	 */
	private readonly _transitMountPath: string;

	/**
	 * The base URL for the Vault API.
	 * @internal
	 */
	private readonly _baseUrl: string;

	/**
	 * The request options for fetch calls.
	 * @internal
	 */
	private readonly _requestOptions: { headers: IHttpHeaders; timeoutMs?: number };

	/**
	 * A prefix for the keys stored in the vault.
	 * @internal
	 */
	private readonly _prefix?: string;

	/**
	 * The TTL in milliseconds for cached key metadata.
	 * @internal
	 */
	private readonly _keyMetadataCacheTtlMs: number;

	/**
	 * Cache of key metadata by key name, undefined when caching is disabled.
	 * @internal
	 */
	private _keyMetadataCache?: LruCache<IReadKeyResponse>;

	/**
	 * Create a new instance of HashicorpVaultConnector.
	 * @param options The options for the vault connector.
	 */
	constructor(options: IHashicorpVaultConnectorConstructorOptions) {
		Guards.object(HashicorpVaultConnector.CLASS_NAME, nameof(options), options);
		Guards.object<IHashicorpVaultConnectorConfig>(
			HashicorpVaultConnector.CLASS_NAME,
			nameof(options.config),
			options.config
		);
		Guards.stringValue(
			HashicorpVaultConnector.CLASS_NAME,
			nameof(options.config.endpoint),
			options.config.endpoint
		);
		Guards.stringValue(
			HashicorpVaultConnector.CLASS_NAME,
			nameof(options.config.token),
			options.config.token
		);

		this._config = options.config;
		this._kvMountPath = this._config.kvMountPath ?? "secret";
		this._transitMountPath = this._config.transitMountPath ?? "transit";
		this._baseUrl = `${StringHelper.trimTrailingSlashes(this._config.endpoint)}/${this._config.apiVersion ?? "v1"}`;
		const headers: IHttpHeaders = {
			"X-Vault-Token": this._config.token
		};
		if (Is.stringValue(this._config.namespace)) {
			headers["X-Vault-Namespace"] = this._config.namespace;
		}
		this._requestOptions = {
			headers,
			timeoutMs: this._config.timeoutMs
		};
		this._prefix = this._config.prefix;
		this._keyMetadataCacheTtlMs =
			this._config.keyMetadataCacheTtlMs ??
			HashicorpVaultConnector._DEFAULT_KEY_METADATA_CACHE_TTL_MS;
		this._keyMetadataCache =
			this._keyMetadataCacheTtlMs > 0
				? new LruCache<IReadKeyResponse>({ ttiMs: this._keyMetadataCacheTtlMs })
				: undefined;
	}

	/**
	 * Returns the class name of the component.
	 * @returns The class name of the component.
	 */
	public className(): string {
		return HashicorpVaultConnector.CLASS_NAME;
	}

	/**
	 * Returns the health status of the component.
	 * @returns The health status of the component.
	 */
	public async health(): Promise<IHealth[]> {
		const endpoint = `${this._baseUrl}/sys/health`;
		try {
			await FetchHelper.fetch(
				HashicorpVaultConnector.CLASS_NAME,
				endpoint,
				HttpMethod.GET,
				undefined,
				this._requestOptions
			);

			return [
				{
					source: HashicorpVaultConnector.CLASS_NAME,
					category: HealthCategory.Connectivity,
					status: HealthStatus.Ok,
					description: "healthDescription",
					data: { endpoint }
				}
			];
		} catch {
			return [
				{
					source: HashicorpVaultConnector.CLASS_NAME,
					category: HealthCategory.Connectivity,
					status: HealthStatus.Error,
					description: "healthDescription",
					message: "vaultHealthCheckFailed",
					data: { endpoint }
				}
			];
		}
	}

	/**
	 * Bootstrap the vault connector and ensure connectivity.
	 * @param nodeLoggingComponentType The node logging component type.
	 * @returns True if the bootstrapping process was successful.
	 */
	public async bootstrap(nodeLoggingComponentType?: string): Promise<boolean> {
		const nodeLogging = ComponentFactory.getIfExists<ILoggingComponent>(nodeLoggingComponentType);

		try {
			await FetchHelper.fetch(
				HashicorpVaultConnector.CLASS_NAME,
				`${this._baseUrl}/sys/health`,
				HttpMethod.GET,
				undefined,
				this._requestOptions
			);

			await nodeLogging?.log({
				level: "info",
				source: HashicorpVaultConnector.CLASS_NAME,
				ts: Date.now(),
				message: "hashicorpVaultConnected",
				data: {
					address: this._config.endpoint
				}
			});

			return true;
		} catch (err) {
			await nodeLogging?.log({
				level: "error",
				source: HashicorpVaultConnector.CLASS_NAME,
				ts: Date.now(),
				message: "hashicorpVaultConnectionFailed",
				error: BaseError.fromError(err),
				data: {
					address: this._config.endpoint
				}
			});
			return false;
		}
	}

	/**
	 * Store a secret in the vault.
	 * @param name The name of the item in the vault to set.
	 * @param data The item to add to the vault.
	 * @returns A promise that resolves when the secret has been stored.
	 */
	public async setSecret<T>(name: string, data: T): Promise<void> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.defined(HashicorpVaultConnector.CLASS_NAME, nameof(data), data);

		try {
			const path = this.getSecretPath(name);
			const url = `${this._baseUrl}/${path}`;
			const payload = {
				data: {
					secret: data
				}
			};

			await FetchHelper.fetchJson<IHashicorpVaultRequest<T>, unknown>(
				HashicorpVaultConnector.CLASS_NAME,
				url,
				HttpMethod.POST,
				payload,
				this._requestOptions
			);
		} catch (err) {
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "setSecretFailed", { name }, err);
		}
	}

	/**
	 * Stop the component and release the key metadata cache.
	 * @param nodeLoggingComponentType The node logging component type.
	 * @returns A promise that resolves when the component has stopped.
	 */
	public async stop(nodeLoggingComponentType?: string): Promise<void> {
		this._keyMetadataCache?.destroy();
		this._keyMetadataCache = undefined;
	}

	/**
	 * Check if a secret exists in the vault.
	 * @param name The name of the secret to check.
	 * @returns True if the secret exists, false otherwise.
	 */
	public async secretExists(name: string): Promise<boolean> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		try {
			await this.getSecretVersions(name);
			return true;
		} catch (err) {
			if (BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				return false;
			}
			throw err;
		}
	}

	/**
	 * Get a secret from the vault.
	 * @param name The name of the item in the vault to get.
	 * @returns The item from the vault.
	 * @throws Error if the item is not found.
	 */
	public async getSecret<T>(name: string): Promise<T> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		await this.getSecretVersions(name);

		try {
			const path = this.getSecretPath(name);
			const url = `${this._baseUrl}/${path}`;

			const response = await FetchHelper.fetchJson<never, IHashicorpVaultResponse<ISecretData<T>>>(
				HashicorpVaultConnector.CLASS_NAME,
				url,
				HttpMethod.GET,
				undefined,
				this._requestOptions
			);

			return response.data.data.secret;
		} catch (err) {
			if (
				Is.object<{ properties?: { httpStatus?: number } }>(err) &&
				err.properties?.httpStatus === 404
			) {
				throw new NotFoundError(
					HashicorpVaultConnector.CLASS_NAME,
					"secretNotFound",
					name,
					undefined,
					err
				);
			}
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "setSecretFailed", { name }, err);
		}
	}

	/**
	 * Remove a secret from the vault.
	 * @param name The name of the item in the vault to remove.
	 * @returns A promise that resolves when the secret has been removed.
	 * @throws Error if the item is not found.
	 */
	public async removeSecret(name: string): Promise<void> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		await this.getSecretVersions(name);

		try {
			const path = this.getSecretMetadataPath(name);
			const url = `${this._baseUrl}/${path}`;

			await FetchHelper.fetchJson<never, IHashicorpVaultResponse<unknown>>(
				HashicorpVaultConnector.CLASS_NAME,
				url,
				HttpMethod.DELETE,
				undefined,
				this._requestOptions
			);
		} catch (err) {
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"removeSecretFailed",
				{ name },
				err
			);
		}
	}

	/**
	 * Generate a new key and store it in the vault.
	 * @param name The name of the key to generate and store in the vault.
	 * @param type The type of key to create.
	 * @returns The public key for the key pair.
	 */
	public async createKey(name: string, type: VaultKeyType): Promise<Uint8Array> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultKeyType>(
			HashicorpVaultConnector.CLASS_NAME,
			nameof(type),
			type,
			Object.values(VaultKeyType)
		);

		const path = this.getTransitKeyPath(name);
		const url = `${this._baseUrl}/${path}`;

		try {
			// Check if the key exists
			const existingVaultKey = await this.readKey(name);
			if (existingVaultKey) {
				throw new AlreadyExistsError(HashicorpVaultConnector.CLASS_NAME, "keyAlreadyExists", name);
			}
		} catch (err) {
			if (!BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				throw err;
			}
		}

		try {
			const vaultKeyType = this.mapVaultKeyType(type);

			const payload: ICreateKeyRequest = {
				type: vaultKeyType,
				exportable: true,
				allow_plaintext_backup: true // eslint-disable-line camelcase
			};

			await FetchHelper.fetchJson<ICreateKeyRequest, IHashicorpVaultResponse<unknown>>(
				HashicorpVaultConnector.CLASS_NAME,
				url,
				HttpMethod.POST,
				payload,
				this._requestOptions
			);
			this._keyMetadataCache?.delete(name);

			// If the key is asymmetric, return the public key
			if (this.isAsymmetricKeyType(type)) {
				const publicKey = await this.exportKey(name, "public-key");
				return publicKey.key;
			}

			// If the key is symmetric, return the encryption key
			const symmetricKey = await this.exportKey(name, "encryption-key");
			return symmetricKey.key;
		} catch (err) {
			if (BaseError.isErrorName(err, AlreadyExistsError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"createKeyFailed",
				{ name, type },
				err
			);
		}
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
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultKeyType>(
			HashicorpVaultConnector.CLASS_NAME,
			nameof(type),
			type,
			Object.values(VaultKeyType)
		);
		Guards.uint8Array(HashicorpVaultConnector.CLASS_NAME, nameof(privateKey), privateKey);

		try {
			// Check if the key exists
			const existingVaultKey = await this.readKey(name);
			if (existingVaultKey) {
				throw new AlreadyExistsError(HashicorpVaultConnector.CLASS_NAME, "keyAlreadyExists", name);
			}
		} catch (err) {
			if (!BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				throw err;
			}
		}

		try {
			const internalType = this.mapVaultKeyTypeToIndex(type);

			let publicKeyForPayload: string | null = null;
			let privateKeyForPayload: string | null = null;

			if (type === VaultKeyType.Ed25519 || type === VaultKeyType.ChaCha20Poly1305) {
				const combinedKey = new Uint8Array(privateKey.length + (publicKey?.length ?? 0));
				combinedKey.set(privateKey);
				if (publicKey) {
					combinedKey.set(publicKey, privateKey.length);
				}
				privateKeyForPayload = Converter.bytesToBase64(combinedKey);
				if (!Is.undefined(publicKey)) {
					publicKeyForPayload = Converter.bytesToBase64(publicKey);
				}
			}

			const payload = {
				policy: {
					name,
					keys: {
						"1": {
							key: privateKeyForPayload,
							hmac_key: Converter.bytesToBase64(RandomHelper.generate(32)), // eslint-disable-line camelcase
							public_key: publicKeyForPayload // eslint-disable-line camelcase
						}
					},
					exportable: true,
					allow_plaintext_backup: true, // eslint-disable-line camelcase
					min_decryption_version: 1, // eslint-disable-line camelcase
					min_encryption_version: 0, // eslint-disable-line camelcase
					latest_version: 1, // eslint-disable-line camelcase
					type: internalType
				}
			};

			const json = JSON.stringify(payload);

			const backup = Converter.bytesToBase64(Converter.utf8ToBytes(json));

			await this.restoreKey(name, backup);
		} catch (err) {
			if (BaseError.isErrorName(err, AlreadyExistsError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"addKeyFailed",
				{ name, type },
				err
			);
		}
	}

	/**
	 * Get a key from the vault.
	 * @param name The name of the key to get.
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
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		components ??= "both";

		Guards.arrayOneOf<"public" | "private" | "both">(
			HashicorpVaultConnector.CLASS_NAME,
			nameof(components),
			components,
			["public", "private", "both"]
		);

		const keyDetails = await this.readKeyCached(name);

		const type = this.mapHashicorpKeyType(keyDetails.type);
		const isAsymmetric = this.isAsymmetricKeyType(type);

		if (!isAsymmetric && components === "private") {
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "symmetricKeyHasNoPrivateKey", {
				name
			});
		}

		try {
			let publicKey: Uint8Array | undefined;
			let privateKey: Uint8Array | undefined;

			if (isAsymmetric) {
				if (components !== "public") {
					const privateKeyData = await this.exportKey(name, "signing-key");
					privateKey = privateKeyData.key;
				}
				if (components !== "private") {
					const publicKeyData = await this.exportKey(name, "public-key");
					publicKey = publicKeyData.key;
				}
			} else if (components !== "public") {
				const privateKeyData = await this.exportKey(name, "encryption-key");
				privateKey = privateKeyData.key;
			}

			return { type, privateKey, publicKey };
		} catch (err) {
			if (BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "getKeyFailed", { name }, err);
		}
	}

	/**
	 * Check if a key exists in the vault.
	 * @param name The name of the key to check.
	 * @returns True if the key exists, false otherwise.
	 */
	public async keyExists(name: string): Promise<boolean> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		try {
			await this.readKey(name);
			return true;
		} catch (err) {
			if (BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				return false;
			}
			throw err;
		}
	}

	/**
	 * Get the type of a key from the vault without retrieving the key material.
	 * @param name The name of the key.
	 * @returns The key type.
	 * @throws NotFoundError if the key does not exist.
	 */
	public async getKeyType(name: string): Promise<VaultKeyType> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		const keyDetails = await this.readKeyCached(name);

		return this.mapHashicorpKeyType(keyDetails.type);
	}

	/**
	 * Rename a key in the vault.
	 * @param name The name of the key to rename.
	 * @param newName The new name of the key.
	 * @returns A promise that resolves when the key has been renamed.
	 */
	public async renameKey(name: string, newName: string): Promise<void> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(newName), newName);

		await this.readKey(name);

		let existingVaultKey;
		try {
			existingVaultKey = await this.readKey(newName);
		} catch (err) {
			if (!BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				throw err;
			}
		}
		if (existingVaultKey) {
			throw new AlreadyExistsError(HashicorpVaultConnector.CLASS_NAME, "keyAlreadyExists", newName);
		}

		try {
			const backup = await this.backupKey(name);
			await this.restoreKey(newName, backup);
			await this.removeKey(name);
		} catch (err) {
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"renameKeyFailed",
				{ name, newName },
				err
			);
		}
	}

	/**
	 * Remove a key from the vault.
	 * @param name The name of the key to remove.
	 * @returns A promise that resolves when the key has been removed.
	 */
	public async removeKey(name: string): Promise<void> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		await this.readKey(name);

		try {
			const path = this.getTransitKeyPath(name);
			const url = `${this._baseUrl}/${path}`;

			await this.updateKeyConfig(name, true);

			await FetchHelper.fetch(
				HashicorpVaultConnector.CLASS_NAME,
				url,
				HttpMethod.DELETE,
				undefined,
				this._requestOptions
			);
			this._keyMetadataCache?.delete(name);
		} catch (err) {
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "removeKeyFailed", { name }, err);
		}
	}

	/**
	 * Sign data.
	 * @param name The name of the key to use.
	 * @param data The data to sign.
	 * @returns The signature.
	 */
	public async sign(name: string, data: Uint8Array): Promise<Uint8Array> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.uint8Array(HashicorpVaultConnector.CLASS_NAME, nameof(data), data);

		await this.readKeyCached(name);

		try {
			const path = this.getTransitSignPath(name);
			const url = `${this._baseUrl}/${path}`;

			const base64Data = Converter.bytesToBase64(data);

			const payload = {
				input: base64Data
			};

			const response = await FetchHelper.fetchJson<
				ISignDataRequest,
				IHashicorpVaultResponse<ISignDataResponse>
			>(HashicorpVaultConnector.CLASS_NAME, url, HttpMethod.POST, payload, this._requestOptions);

			if (response?.data?.signature) {
				const signatureString = response.data.signature;

				const cleanedSignature = signatureString.startsWith(HashicorpVaultConnector._DATA_PREFIX)
					? signatureString.slice(HashicorpVaultConnector._DATA_PREFIX.length)
					: signatureString;

				const signatureBytes = Converter.base64ToBytes(cleanedSignature);
				return signatureBytes;
			}
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "invalidSignResponse", { name });
		} catch (err) {
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "signDataFailed", { name }, err);
		}
	}

	/**
	 * Verify a signature.
	 * @param name The name of the key to use.
	 * @param data The data to verify.
	 * @param signature The signature to verify.
	 * @returns True if the signature is valid.
	 */
	public async verify(name: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.uint8Array(HashicorpVaultConnector.CLASS_NAME, nameof(data), data);
		Guards.uint8Array(HashicorpVaultConnector.CLASS_NAME, nameof(signature), signature);

		await this.readKeyCached(name);

		try {
			const path = this.getTransitVerifyPath(name);
			const url = `${this._baseUrl}/${path}`;

			const base64Data = Converter.bytesToBase64(data);
			const signatureBase64 = Converter.bytesToBase64(signature);

			const prefixedSignature = `${HashicorpVaultConnector._DATA_PREFIX}${signatureBase64}`;

			const payload = {
				input: base64Data,
				signature: prefixedSignature
			};

			const response = await FetchHelper.fetchJson<
				IVerifyDataRequest,
				IHashicorpVaultResponse<IVerifyDataResponse>
			>(HashicorpVaultConnector.CLASS_NAME, url, HttpMethod.POST, payload, this._requestOptions);

			if (response?.data?.valid) {
				return response.data.valid;
			}

			return false;
		} catch (err) {
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "verifyDataFailed", { name }, err);
		}
	}

	/**
	 * Encrypt data locally under a data key wrapped by the transit key.
	 * @param name The name of the key to use.
	 * @param encryptionType The type of encryption to use.
	 * @param data The data to encrypt.
	 * @returns The encrypted data.
	 */
	public async encrypt(
		name: string,
		encryptionType: VaultEncryptionType,
		data: Uint8Array
	): Promise<Uint8Array> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultEncryptionType>(
			HashicorpVaultConnector.CLASS_NAME,
			nameof(encryptionType),
			encryptionType,
			Object.values(VaultEncryptionType)
		);
		Guards.uint8Array(HashicorpVaultConnector.CLASS_NAME, nameof(data), data);

		const keyDetails = await this.readKeyCached(name);

		if (
			encryptionType === VaultEncryptionType.ChaCha20Poly1305 &&
			keyDetails.type !== this.mapVaultKeyType(VaultKeyType.ChaCha20Poly1305)
		) {
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "keyTypeMismatch", {
				encryptionType,
				keyType: keyDetails.type
			});
		}

		try {
			const dataKey = RandomHelper.generate(HashicorpVaultConnector._DATA_KEY_LENGTH);
			const wrappedKey = await this.transitEncrypt(name, dataKey);
			const header = this.buildEnvelopeHeader(wrappedKey);
			const nonce = RandomHelper.generate(HashicorpVaultConnector._NONCE_LENGTH);
			const payload = new ChaCha20Poly1305(dataKey, nonce, header).encrypt(data);
			dataKey.fill(0);

			const envelope = new Uint8Array(header.length + nonce.length + payload.length);
			envelope.set(header);
			envelope.set(nonce, header.length);
			envelope.set(payload, header.length + nonce.length);
			return envelope;
		} catch (err) {
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"encryptDataFailed",
				{ name, encryptionType },
				err
			);
		}
	}

	/**
	 * Decrypt data, either an envelope or data encrypted directly by the transit key.
	 * @param name The name of the key to use.
	 * @param encryptionType The type of encryption to use.
	 * @param encryptedData The encrypted data to decrypt.
	 * @returns The decrypted data.
	 */
	public async decrypt(
		name: string,
		encryptionType: VaultEncryptionType,
		encryptedData: Uint8Array
	): Promise<Uint8Array> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.arrayOneOf<VaultEncryptionType>(
			HashicorpVaultConnector.CLASS_NAME,
			nameof(encryptionType),
			encryptionType,
			Object.values(VaultEncryptionType)
		);
		Guards.uint8Array(HashicorpVaultConnector.CLASS_NAME, nameof(encryptedData), encryptedData);

		await this.readKeyCached(name);

		try {
			if (!this.hasEnvelopePrefix(encryptedData)) {
				return await this.transitDecrypt(
					name,
					`${HashicorpVaultConnector._DATA_PREFIX}${Converter.bytesToBase64(encryptedData)}`
				);
			}

			const envelope = this.parseEnvelope(encryptedData);
			const dataKey = await this.transitDecrypt(name, envelope.wrappedKey);
			const decrypted = new ChaCha20Poly1305(dataKey, envelope.nonce, envelope.header).decrypt(
				envelope.payload
			);
			dataKey.fill(0);
			return decrypted;
		} catch (err) {
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"decryptDataFailed",
				{ name, encryptionType },
				err
			);
		}
	}

	/**
	 * Get the versions of a secret.
	 * @param name The name of the secret.
	 * @returns The versions of the secret.
	 * @throws Error if the secret is not found.
	 */
	public async getSecretVersions(name: string): Promise<number[]> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		try {
			const versions = await this.fetchSecretVersions(name);
			return versions;
		} catch (err) {
			if (BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"getSecretVersionsFailed",
				{ name },
				err
			);
		}
	}

	/**
	 * Update the configuration of a key.
	 * @param name The name of the key to update.
	 * @param deletionAllowed Whether the key can be deleted.
	 * @param exportable Whether the key can be exported.
	 * @returns A promise that resolves when the key configuration has been updated.
	 */
	public async updateKeyConfig(
		name: string,
		deletionAllowed?: boolean,
		exportable?: boolean
	): Promise<void> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		try {
			const path = this.getTransitKeyConfigPath(name);
			const url = `${this._baseUrl}/${path}`;

			const payload = {
				deletion_allowed: deletionAllowed, // eslint-disable-line camelcase
				exportable
			};

			await FetchHelper.fetchJson<IUpdateKeyConfigRequest, IHashicorpVaultResponse<unknown>>(
				HashicorpVaultConnector.CLASS_NAME,
				url,
				HttpMethod.POST,
				payload,
				this._requestOptions
			);
		} catch (err) {
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"updateKeyConfigFailed",
				{ name },
				err
			);
		}
	}

	/**
	 * Backup a key from the vault.
	 * @param name The name of the key to backup.
	 * @returns The Base64-encoded backup payload.
	 * @throws Error if the key cannot be exported or found.
	 */
	public async backupKey(name: string): Promise<string> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		const path = this.getTransitBackupKeyPath(name);
		const url = `${this._baseUrl}/${path}`;

		try {
			const response = await FetchHelper.fetchJson<
				never,
				IHashicorpVaultResponse<IBackupKeyResponse>
			>(HashicorpVaultConnector.CLASS_NAME, url, HttpMethod.GET, undefined, this._requestOptions);

			if (response?.data?.backup) {
				const backup = response.data.backup;
				return backup;
			}

			throw new NotFoundError(HashicorpVaultConnector.CLASS_NAME, "backupKeyNotFound", name);
		} catch (err) {
			if (BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "backupKeyFailed", { name }, err);
		}
	}

	/**
	 * Restore a key to the vault.
	 * @param name The name of the key to restore.
	 * @param backup The Base64-encoded backup payload.
	 * @returns A promise that resolves when the key has been restored.
	 * @throws Error if the key cannot be restored.
	 */
	public async restoreKey(name: string, backup: string): Promise<void> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(backup), backup);

		const path = this.getTransitRestoreKeyPath(name);
		const url = `${this._baseUrl}/${path}`;

		try {
			const payload = { backup };

			await FetchHelper.fetchJson<IRestoreKeyRequest, IHashicorpVaultResponse<unknown>>(
				HashicorpVaultConnector.CLASS_NAME,
				url,
				HttpMethod.POST,
				payload,
				this._requestOptions
			);
			this._keyMetadataCache?.delete(name);
		} catch (err) {
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "restoreKeyFailed", { name }, err);
		}
	}

	/**
	 * Import a key to the vault.
	 * @param name The name of the key to import.
	 * @param type The type of key to import, e.g. "ed25519".
	 * @param privateKeyPem The PEM bundle of the key to import.
	 * @returns A promise that resolves when the key has been imported.
	 * @throws Error if the key cannot be imported.
	 */
	public async importKey(name: string, type: string, privateKeyPem: string): Promise<void> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(privateKeyPem), privateKeyPem);

		const path = this.getTransitImportKeyPath(name);
		const url = `${this._baseUrl}/${path}`;

		try {
			const payload = {
				type,
				key: Converter.bytesToBase58(Converter.utf8ToBytes(privateKeyPem)),
				exportable: true,
				// eslint-disable-next-line camelcase
				allow_plaintext_backup: true
			};

			await FetchHelper.fetchJson<IImportKeyRequest, IHashicorpVaultResponse<unknown>>(
				HashicorpVaultConnector.CLASS_NAME,
				url,
				HttpMethod.POST,
				payload,
				this._requestOptions
			);
			this._keyMetadataCache?.delete(name);
		} catch (err) {
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "importKeyFailed", { name }, err);
		}
	}

	/**
	 * Export the key from the vault.
	 * @param name The name of the key.
	 * @param keyPath The path of the key. Defaults to "signing-key".
	 * @param version The version of the key. If omitted, all versions of the key will be returned.
	 * @returns The key details.
	 * @throws Error if the key cannot be exported or found.
	 */
	public async exportKey(
		name: string,
		keyPath: "signing-key" | "encryption-key" | "public-key",
		version?: string
	): Promise<{
		/**
		 * The type of the key e.g. Ed25519.
		 */
		type: VaultKeyType;

		/**
		 * The key.
		 */
		key: Uint8Array;

		/**
		 * The name of the key.
		 */
		name: string;
	}> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		const versionPath = version ? `${version}` : "latest";

		const path = this.getTransitExportKeyPath(name, keyPath);
		const url = `${this._baseUrl}/${path}/${versionPath}`;

		try {
			const response = await FetchHelper.fetchJson<
				never,
				IHashicorpVaultResponse<IExportKeyResponse>
			>(HashicorpVaultConnector.CLASS_NAME, url, HttpMethod.GET, undefined, this._requestOptions);

			if (response?.data) {
				const { keys, type } = response.data;
				const keyVersion = Object.keys(keys)[0];
				let key;

				const keyType = this.mapHashicorpKeyType(type);
				if (keyType === VaultKeyType.Ed25519) {
					key = Converter.base64ToBytes(keys[keyVersion]).slice(
						0,
						keyPath === "public-key" ? Ed25519.PUBLIC_KEY_SIZE : Ed25519.PRIVATE_KEY_SIZE
					);
				} else {
					// VaultKeyType.ChaCha20Poly1305
					key = Converter.base64ToBytes(keys[keyVersion]);
				}

				const keyData = {
					type: keyType,
					key,
					name: response?.data?.name
				};

				return keyData;
			}

			throw new NotFoundError(HashicorpVaultConnector.CLASS_NAME, "exportKeyNotFound", name);
		} catch (err) {
			if (BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"exportKeyFailed",
				{ name, keyPath },
				err
			);
		}
	}

	/**
	 * Get the key configuration.
	 * @param name The name of the key to get the configuration for.
	 * @returns True if the key can be deleted.
	 */
	public async getKeyDeleteConfiguration(name: string): Promise<boolean> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);
		const path = this.getTransitKeyPath(name);
		const url = `${this._baseUrl}/${path}`;

		try {
			const response = await FetchHelper.fetchJson<
				never,
				IHashicorpVaultResponse<IKeyDeleteConfigResponse>
			>(HashicorpVaultConnector.CLASS_NAME, url, HttpMethod.GET, undefined, this._requestOptions);

			return response.data.deletion_allowed;
		} catch (err) {
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"getKeyDeleteConfigurationFailed",
				{ name },
				err
			);
		}
	}

	/**
	 * Read key information from the vault.
	 * @param name The name of the key.
	 * @returns An object containing key information.
	 * @internal
	 */
	private async readKey(name: string): Promise<IReadKeyResponse> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		const path = this.getTransitKeyPath(name);
		const url = `${this._baseUrl}/${path}`;

		try {
			const response = await FetchHelper.fetchJson<
				never,
				IHashicorpVaultResponse<IReadKeyResponse>
			>(HashicorpVaultConnector.CLASS_NAME, url, HttpMethod.GET, undefined, this._requestOptions);

			if (response?.data?.name) {
				const keyName = response.data.name;
				return { name: keyName, type: response.data.type };
			}
			throw new NotFoundError(HashicorpVaultConnector.CLASS_NAME, "keyNotFound", name);
		} catch (err) {
			if (this.isHttpNotFoundError(err)) {
				throw new NotFoundError(
					HashicorpVaultConnector.CLASS_NAME,
					"keyNotFound",
					name,
					undefined,
					err
				);
			}
			if (BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"invalidReadKeyResponse",
				{ name },
				err
			);
		}
	}

	/**
	 * Read key metadata, served from the cache when it is enabled.
	 * @param name The name of the key.
	 * @returns An object containing key information.
	 * @internal
	 */
	private async readKeyCached(name: string): Promise<IReadKeyResponse> {
		const cached = this._keyMetadataCache?.get(name);
		if (!Is.undefined(cached)) {
			return cached;
		}

		const keyDetails = await this.readKey(name);
		this._keyMetadataCache?.set(name, keyDetails, Date.now() + this._keyMetadataCacheTtlMs);
		return keyDetails;
	}

	/**
	 * Encrypt bytes with the transit key.
	 * @param name The name of the key.
	 * @param data The bytes to encrypt.
	 * @returns The transit ciphertext including its version prefix.
	 * @internal
	 */
	private async transitEncrypt(name: string, data: Uint8Array): Promise<string> {
		const url = `${this._baseUrl}/${this.getTransitEncryptPath(name)}`;
		const payload = { plaintext: Converter.bytesToBase64(data) };

		const response = await FetchHelper.fetchJson<
			IEncryptDataRequest,
			IHashicorpVaultResponse<IEncryptDataResponse>
		>(HashicorpVaultConnector.CLASS_NAME, url, HttpMethod.POST, payload, this._requestOptions);

		if (Is.stringValue(response?.data?.ciphertext)) {
			return response.data.ciphertext;
		}
		throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "invalidEncryptResponse", { name });
	}

	/**
	 * Decrypt a transit ciphertext with the transit key.
	 * @param name The name of the key.
	 * @param ciphertext The transit ciphertext including its version prefix.
	 * @returns The decrypted bytes.
	 * @internal
	 */
	private async transitDecrypt(name: string, ciphertext: string): Promise<Uint8Array> {
		const url = `${this._baseUrl}/${this.getTransitDecryptPath(name)}`;
		const payload = { ciphertext };

		const response = await FetchHelper.fetchJson<
			IDecryptDataRequest,
			IHashicorpVaultResponse<IDecryptDataResponse>
		>(HashicorpVaultConnector.CLASS_NAME, url, HttpMethod.POST, payload, this._requestOptions);

		if (Is.stringValue(response?.data?.plaintext)) {
			return Converter.base64ToBytes(response.data.plaintext);
		}
		throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "invalidDecryptResponse", { name });
	}

	/**
	 * Check whether the data starts with the envelope prefix.
	 * @param data The data to check.
	 * @returns True if the data is an envelope.
	 * @internal
	 */
	private hasEnvelopePrefix(data: Uint8Array): boolean {
		return HashicorpVaultConnector._ENVELOPE_PREFIX.every((byte, index) => data[index] === byte);
	}

	/**
	 * Build the envelope header, the prefix followed by the length prefixed wrapped data key.
	 * @param wrappedKey The transit ciphertext of the data key.
	 * @returns The header bytes.
	 * @internal
	 */
	private buildEnvelopeHeader(wrappedKey: string): Uint8Array {
		const prefix = HashicorpVaultConnector._ENVELOPE_PREFIX;
		const wrappedBytes = Converter.utf8ToBytes(wrappedKey);
		const header = new Uint8Array(prefix.length + 2 + wrappedBytes.length);
		header.set(prefix);
		new DataView(header.buffer).setUint16(prefix.length, wrappedBytes.length);
		header.set(wrappedBytes, prefix.length + 2);
		return header;
	}

	/**
	 * Split an envelope into its header, wrapped data key, nonce and payload.
	 * @param envelope The envelope bytes.
	 * @returns The envelope parts.
	 * @throws GeneralError if the envelope is shorter than its header declares.
	 * @internal
	 */
	private parseEnvelope(envelope: Uint8Array): IDataKeyEnvelope {
		const lengthOffset = HashicorpVaultConnector._ENVELOPE_PREFIX.length;
		const wrappedLength =
			envelope.length >= lengthOffset + 2
				? new DataView(envelope.buffer, envelope.byteOffset).getUint16(lengthOffset)
				: 0;
		const headerLength = lengthOffset + 2 + wrappedLength;
		const payloadOffset = headerLength + HashicorpVaultConnector._NONCE_LENGTH;

		if (envelope.length < payloadOffset + HashicorpVaultConnector._TAG_LENGTH) {
			throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "invalidEnvelope", {
				length: envelope.length
			});
		}

		return {
			header: envelope.slice(0, headerLength),
			wrappedKey: Converter.bytesToUtf8(envelope, lengthOffset + 2, wrappedLength),
			nonce: envelope.slice(headerLength, payloadOffset),
			payload: envelope.slice(payloadOffset)
		};
	}

	/**
	 * Determine whether an error is a framework missing-key error.
	 * @param err The error to inspect.
	 * @returns True if the error is a NotFoundError.
	 * @internal
	 */
	/**
	 * Determine whether a Vault request reported a missing key.
	 * @param err The error to inspect.
	 * @returns True if the error has an HTTP 404 status.
	 * @internal
	 */
	private isHttpNotFoundError(err: unknown): boolean {
		return (
			Is.object<{ properties?: { httpStatus?: number } }>(err) && err.properties?.httpStatus === 404
		);
	}

	/**
	 * Map the vault key type to the hashicorp type.
	 * @param type The vault key type.
	 * @returns The hashicorp type as a string.
	 * @throws Error if the key type is not supported.
	 * @internal
	 */
	private mapVaultKeyType(type: VaultKeyType): string {
		switch (type) {
			case VaultKeyType.Ed25519:
				return "ed25519";
			case VaultKeyType.ChaCha20Poly1305:
				return "chacha20-poly1305";
			default:
				throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "unsupportedKeyType", { type });
		}
	}

	/**
	 * Map the vault key type to the hashicorp type index.
	 * @param type The vault key type.
	 * @returns The hashicorp type as a string.
	 * @throws Error if the key type is not supported.
	 * @internal
	 */
	private mapVaultKeyTypeToIndex(type: VaultKeyType): number {
		// https://github.com/hashicorp/vault/blob/7d89f7104ed6c98e06ca2c75da20c9ef1b113831/sdk/helper/keysutil/policy.go#L58
		switch (type) {
			case VaultKeyType.Ed25519:
				return 2;
			case VaultKeyType.ChaCha20Poly1305:
				return 5;
			default:
				throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "unsupportedKeyType", { type });
		}
	}

	/**
	 * Map the hashicorp key type to the vault type.
	 * @param type The hashicorp key type.
	 * @returns The vault key type.
	 * @throws Error if the key type is not supported.
	 * @internal
	 */
	private mapHashicorpKeyType(type: string): VaultKeyType {
		switch (type) {
			case "ed25519":
				return VaultKeyType.Ed25519;
			case "chacha20-poly1305":
				return VaultKeyType.ChaCha20Poly1305;
			default:
				throw new GeneralError(HashicorpVaultConnector.CLASS_NAME, "unsupportedKeyType", { type });
		}
	}

	/**
	 * Check if the key type is asymmetric.
	 * @param type The key type.
	 * @returns True if the key type is asymmetric.
	 * @internal
	 */
	private isAsymmetricKeyType(type: VaultKeyType): boolean {
		switch (type) {
			case VaultKeyType.Ed25519:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Fetch the versions of a secret.
	 * @param name The name of the secret.
	 * @returns The versions of the secret.
	 * @throws Error if the secret is not found.
	 * @internal
	 */
	private async fetchSecretVersions(name: string): Promise<number[]> {
		Guards.stringValue(HashicorpVaultConnector.CLASS_NAME, nameof(name), name);

		try {
			const path = this.getSecretMetadataPath(name);
			const url = `${this._baseUrl}/${path}`;

			const response = await FetchHelper.fetchJson<
				never,
				IHashicorpVaultResponse<ISecretVersionResponse>
			>(HashicorpVaultConnector.CLASS_NAME, url, HttpMethod.GET, undefined, this._requestOptions);

			if (response?.data?.versions) {
				const versions = Object.keys(response.data.versions).map(Number);
				return versions;
			}
			throw new NotFoundError(HashicorpVaultConnector.CLASS_NAME, "secretNotFound", name);
		} catch (err) {
			if (this.isHttpNotFoundError(err)) {
				throw new NotFoundError(
					HashicorpVaultConnector.CLASS_NAME,
					"secretNotFound",
					name,
					undefined,
					err
				);
			}
			if (BaseError.isErrorName(err, NotFoundError.CLASS_NAME)) {
				throw err;
			}
			throw new GeneralError(
				HashicorpVaultConnector.CLASS_NAME,
				"getSecretVersionsFailed",
				{ name },
				err
			);
		}
	}

	/**
	 * Encode the name parameter.
	 * @param name The name to encode.
	 * @returns The encoded name.
	 * @internal
	 */
	private getEncodedName(name: string): string {
		const safeName = name.replace(/[^\dA-Za-z-]/g, "_").replace(/[_-]+$/, "");

		return Is.stringValue(this._prefix)
			? `${encodeURIComponent(this._prefix)}_${safeName}`
			: safeName;
	}

	/**
	 * Get the path for a secret.
	 * @param name The name of the secret.
	 * @returns The path for the secret.
	 * @internal
	 */
	private getSecretPath(name: string): string {
		return `${this._kvMountPath}/data/${this.getEncodedName(name)}`;
	}

	/**
	 * Get the path for the metadata of a secret.
	 * @param name The name of the secret.
	 * @returns The path for the metadata of the secret.
	 * @internal
	 */
	private getSecretMetadataPath(name: string): string {
		return `${this._kvMountPath}/metadata/${this.getEncodedName(name)}`;
	}

	/**
	 * Get the path for a Transit key.
	 * @param name The name of the key.
	 * @returns The path for the key.
	 * @internal
	 */
	private getTransitKeyPath(name: string): string {
		return `${this._transitMountPath}/keys/${this.getEncodedName(name)}`;
	}

	/**
	 * Get the path for exporting a Transit key.
	 * @param name The name of the key.
	 * @param keyType The type of the key.
	 * @returns The path for exporting the key.
	 * @internal
	 */
	private getTransitExportKeyPath(name: string, keyType: string): string {
		return `${this._transitMountPath}/export/${keyType}/${this.getEncodedName(name)}`;
	}

	/**
	 * Get the path for the Transit key config.
	 * @param name The name of the key to update.
	 * @returns The path for the key config.
	 * @internal
	 */
	private getTransitKeyConfigPath(name: string): string {
		return `${this._transitMountPath}/keys/${this.getEncodedName(name)}/config`;
	}

	/**
	 * Get the path to backup a Transit key.
	 * @param name The name of the key.
	 * @returns The path for the backup key.
	 * @internal
	 */
	private getTransitBackupKeyPath(name: string): string {
		return `${this._transitMountPath}/backup/${this.getEncodedName(name)}`;
	}

	/**
	 * Get the path for restoring a Transit key.
	 * @param name The name of the key.
	 * @returns The path for the restore key.
	 * @internal
	 */
	private getTransitRestoreKeyPath(name: string): string {
		return `${this._transitMountPath}/restore/${this.getEncodedName(name)}`;
	}

	/**
	 * Get the path for importing a Transit key.
	 * @param name The name of the key.
	 * @returns The path for the import key.
	 * @internal
	 */
	private getTransitImportKeyPath(name: string): string {
		return `${this._transitMountPath}/keys/${this.getEncodedName(name)}/import`;
	}

	/**
	 * Get the path for signing data with a Transit key.
	 * @param name The name of the key.
	 * @returns The path for the sign.
	 * @internal
	 */
	private getTransitSignPath(name: string): string {
		return `${this._transitMountPath}/sign/${this.getEncodedName(name)}`;
	}

	/**
	 * Get the path for verifying data with a Transit key.
	 * @param name The name of the key.
	 * @returns The path for the verify.
	 * @internal
	 */
	private getTransitVerifyPath(name: string): string {
		return `${this._transitMountPath}/verify/${this.getEncodedName(name)}`;
	}

	/**
	 * Get the path for encrypting data with a Transit key.
	 * @param name The name of the key.
	 * @returns The path for encryption.
	 * @internal
	 */
	private getTransitEncryptPath(name: string): string {
		return `${this._transitMountPath}/encrypt/${this.getEncodedName(name)}`;
	}

	/**
	 * Get the path for decrypting data with a Transit key.
	 * @param name The name of the key.
	 * @returns The path for decryption.
	 * @internal
	 */
	private getTransitDecryptPath(name: string): string {
		return `${this._transitMountPath}/decrypt/${this.getEncodedName(name)}`;
	}
}
