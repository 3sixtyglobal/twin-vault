// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { Guards, UnauthorizedError } from "@twin.org/core";
import { nameof } from "@twin.org/nameof";
import { Jwt, type IJwtHeader, type IJwtPayload } from "@twin.org/web";
import type { IVaultConnector } from "../models/IVaultConnector.js";

/**
 * Helpers for vault connectors.
 */
export class VaultConnectorHelper {
	/**
	 * Runtime name for the class.
	 */
	public static readonly CLASS_NAME: string = nameof<VaultConnectorHelper>();

	/**
	 * Sign a JWT using vault connector.
	 * @param vaultConnector The vault connector to use.
	 * @param keyName The name of the key to sign with.
	 * @param header The header to sign.
	 * @param payload The payload to sign.
	 * @returns The token.
	 */
	public static async jwtSigner(
		vaultConnector: IVaultConnector,
		keyName: string,
		header: IJwtHeader,
		payload: IJwtPayload
	): Promise<string> {
		Guards.object<IVaultConnector>(
			VaultConnectorHelper.CLASS_NAME,
			nameof(vaultConnector),
			vaultConnector
		);
		Guards.stringValue(VaultConnectorHelper.CLASS_NAME, nameof(keyName), keyName);
		Guards.object(VaultConnectorHelper.CLASS_NAME, nameof(header), header);
		Guards.object(VaultConnectorHelper.CLASS_NAME, nameof(payload), payload);

		const signingBytes = Jwt.toSigningBytes(header, payload);
		const signatureBytes = await vaultConnector.sign(keyName, signingBytes);
		return Jwt.tokenFromBytes(signingBytes, signatureBytes);
	}

	/**
	 * Verify a JWT using a vault connector.
	 * @param vaultConnector The vault connector to use.
	 * @param keyName The name of the key to verify with.
	 * @param token The token to verify.
	 * @returns The header and payload if verification successful.
	 */
	public static async jwtVerifier<T extends IJwtHeader, U extends IJwtPayload>(
		vaultConnector: IVaultConnector,
		keyName: string,
		token: string
	): Promise<{
		header: T;
		payload: U;
	}> {
		Guards.object<IVaultConnector>(
			VaultConnectorHelper.CLASS_NAME,
			nameof(vaultConnector),
			vaultConnector
		);
		Guards.stringValue(VaultConnectorHelper.CLASS_NAME, nameof(keyName), keyName);
		Guards.stringValue(VaultConnectorHelper.CLASS_NAME, nameof(token), token);

		const { signingBytes, signature } = Jwt.tokenToBytes(token);

		const verified = await vaultConnector.verify(keyName, signingBytes, signature);
		if (!verified) {
			throw new UnauthorizedError(VaultConnectorHelper.CLASS_NAME, "invalidSignature");
		}

		return Jwt.fromSigningBytes(signingBytes);
	}

	/**
	 * Build a key name from parts.
	 * @param keyParts The parts of the key.
	 * @returns The constructed key name.
	 */
	public static buildKeyName(...keyParts: string[]): string {
		return keyParts.join("/");
	}
}
