// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
// Tests for the HashicorpVaultConnector data key envelope.
import { BaseError, Converter, RandomHelper } from "@3sixty/core";
import { ChaCha20Poly1305 } from "@3sixty/crypto";
import { VaultEncryptionType, VaultKeyType } from "@3sixty/vault-models";
import { FetchHelper, HttpMethod } from "@3sixty/web";
import { cleanupKeys, TEST_VAULT_CONFIG } from "./setupTestEnv.js";
import { HashicorpVaultConnector } from "../src/hashicorpVaultConnector.js";

const TEST_KEY_NAME = `test-envelope-key-${Converter.bytesToHex(RandomHelper.generate(8))}`;
const TEST_DATA = Converter.utf8ToBytes("test-data");
const ENVELOPE_PREFIX = Converter.utf8ToBytes("twin:env:v1:");
const TRANSIT_PREFIX = "vault:v1:";
const NONCE_LENGTH = 12;
const LARGE_DATA_LENGTH = 2 * 1024 * 1024;

let vaultConnector: HashicorpVaultConnector;

/**
 * Build a payload larger than the default vault json string value limit.
 * @returns The payload.
 */
function largeData(): Uint8Array {
	const data = new Uint8Array(LARGE_DATA_LENGTH);
	for (let i = 0; i < data.length; i++) {
		data[i] = i % 251;
	}
	return data;
}

/**
 * Build the transit url of an operation on the test key.
 * @param operation The transit operation.
 * @returns The url.
 */
function transitUrl(operation: string): string {
	return `${TEST_VAULT_CONFIG.endpoint}/${TEST_VAULT_CONFIG.apiVersion}/${TEST_VAULT_CONFIG.transitMountPath}/${operation}/${TEST_KEY_NAME}`;
}

/**
 * Call a transit operation on the test key directly.
 * @param operation The transit operation.
 * @param body The request body.
 * @returns The response data.
 */
async function transitRequest<T>(operation: string, body: unknown): Promise<T> {
	const response = await fetch(transitUrl(operation), {
		method: "POST",
		headers: { "X-Vault-Token": TEST_VAULT_CONFIG.token, "Content-Type": "application/json" },
		body: JSON.stringify(body)
	});
	const json = (await response.json()) as { data: T };
	return json.data;
}

/**
 * Split an envelope into its parts.
 * @param envelope The envelope.
 * @returns The header, wrapped key, nonce and payload.
 */
function parseEnvelope(envelope: Uint8Array): {
	header: Uint8Array;
	wrappedKey: string;
	nonce: Uint8Array;
	payload: Uint8Array;
} {
	const lengthOffset = ENVELOPE_PREFIX.length;
	const wrappedLength = new DataView(envelope.buffer, envelope.byteOffset).getUint16(lengthOffset);
	const headerLength = lengthOffset + 2 + wrappedLength;
	return {
		header: envelope.slice(0, headerLength),
		wrappedKey: Converter.bytesToUtf8(envelope.slice(lengthOffset + 2, headerLength)),
		nonce: envelope.slice(headerLength, headerLength + NONCE_LENGTH),
		payload: envelope.slice(headerLength + NONCE_LENGTH)
	};
}

/**
 * Encrypt data with the test key.
 * @param data The data to encrypt.
 * @returns The encrypted data.
 */
async function encrypt(data: Uint8Array): Promise<Uint8Array> {
	return vaultConnector.encrypt(TEST_KEY_NAME, VaultEncryptionType.ChaCha20Poly1305, data);
}

/**
 * Decrypt data with the test key.
 * @param encryptedData The data to decrypt.
 * @returns The decrypted data.
 */
async function decrypt(encryptedData: Uint8Array): Promise<Uint8Array> {
	return vaultConnector.decrypt(TEST_KEY_NAME, VaultEncryptionType.ChaCha20Poly1305, encryptedData);
}

describe("HashicorpVaultConnector envelope", () => {
	beforeEach(async () => {
		vaultConnector = new HashicorpVaultConnector({ config: TEST_VAULT_CONFIG });
		await vaultConnector.bootstrap();
		await cleanupKeys([TEST_KEY_NAME]);
		await vaultConnector.createKey(TEST_KEY_NAME, VaultKeyType.ChaCha20Poly1305);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	test("can encrypt and decrypt data larger than the vault json string value limit", async () => {
		const data = largeData();
		const encrypted = await encrypt(data);
		expect(await decrypt(encrypted)).toEqual(data);
	});

	test("can encrypt data under a data key wrapped by the transit key", async () => {
		const encrypted = await encrypt(TEST_DATA);
		expect(encrypted.slice(0, ENVELOPE_PREFIX.length)).toEqual(ENVELOPE_PREFIX);

		const { header, wrappedKey, nonce, payload } = parseEnvelope(encrypted);
		expect(wrappedKey.startsWith(TRANSIT_PREFIX)).toEqual(true);

		const unwrapped = await transitRequest<{ plaintext: string }>("decrypt", {
			ciphertext: wrappedKey
		});
		const dataKey = Converter.base64ToBytes(unwrapped.plaintext);
		expect(dataKey.length).toEqual(32);
		expect(new ChaCha20Poly1305(dataKey, nonce, header).decrypt(payload)).toEqual(TEST_DATA);
	});

	test("can not decrypt data with the transit key itself", async () => {
		const encrypted = await encrypt(TEST_DATA);
		const { header, nonce, payload } = parseEnvelope(encrypted);
		const transitKey = await vaultConnector.getKey(TEST_KEY_NAME);

		expect(() =>
			new ChaCha20Poly1305(transitKey.privateKey as Uint8Array, nonce, header).decrypt(payload)
		).toThrow();
	});

	test("can use a fresh data key for every encryption", async () => {
		const first = parseEnvelope(await encrypt(TEST_DATA));
		const second = parseEnvelope(await encrypt(TEST_DATA));
		expect(first.wrappedKey).not.toEqual(second.wrappedKey);
		expect(first.payload).not.toEqual(second.payload);
	});

	test("can send only the data key through transit", async () => {
		const fetchJsonSpy = vi.spyOn(FetchHelper, "fetchJson");
		const data = largeData();
		const encrypted = await encrypt(data);
		expect(await decrypt(encrypted)).toEqual(data);

		const encryptCalls = fetchJsonSpy.mock.calls.filter(
			call => call[1] === transitUrl("encrypt") && call[2] === HttpMethod.POST
		);
		expect(encryptCalls).toHaveLength(1);
		expect((encryptCalls[0][3] as { plaintext: string }).plaintext).toHaveLength(44);

		const decryptCalls = fetchJsonSpy.mock.calls.filter(
			call => call[1] === transitUrl("decrypt") && call[2] === HttpMethod.POST
		);
		expect(decryptCalls).toHaveLength(1);
		expect((decryptCalls[0][3] as { ciphertext: string }).ciphertext).toEqual(
			parseEnvelope(encrypted).wrappedKey
		);
	});

	test("can decrypt data encrypted directly by the transit key", async () => {
		const transitEncrypted = await transitRequest<{ ciphertext: string }>("encrypt", {
			plaintext: Converter.bytesToBase64(TEST_DATA)
		});
		const legacyData = Converter.base64ToBytes(
			transitEncrypted.ciphertext.slice(TRANSIT_PREFIX.length)
		);
		expect(await decrypt(legacyData)).toEqual(TEST_DATA);
	});

	test("can fail to decrypt an envelope with a modified payload", async () => {
		const encrypted = await encrypt(TEST_DATA);
		encrypted[encrypted.length - 1] = (encrypted[encrypted.length - 1] + 1) % 256;

		await expect(decrypt(encrypted)).rejects.toMatchObject({
			name: "GeneralError",
			message: "hashicorpVaultConnector.decryptDataFailed"
		});
	});

	test("can fail to decrypt an envelope with a modified wrapped key", async () => {
		const encrypted = await encrypt(TEST_DATA);
		const offset = ENVELOPE_PREFIX.length + 2 + TRANSIT_PREFIX.length;
		encrypted[offset] = (encrypted[offset] + 1) % 256;

		await expect(decrypt(encrypted)).rejects.toMatchObject({
			name: "GeneralError",
			message: "hashicorpVaultConnector.decryptDataFailed"
		});
	});

	test("can fail to decrypt a truncated envelope", async () => {
		const encrypted = await encrypt(TEST_DATA);

		const error = await decrypt(encrypted.slice(0, ENVELOPE_PREFIX.length + 8)).catch(err => err);
		expect(BaseError.isErrorMessage(error, "hashicorpVaultConnector.decryptDataFailed")).toEqual(
			true
		);
		expect(BaseError.someErrorMessage(error, "hashicorpVaultConnector.invalidEnvelope")).toEqual(
			true
		);
	});
});
