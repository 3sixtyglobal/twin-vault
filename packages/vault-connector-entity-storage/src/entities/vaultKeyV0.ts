// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@twin.org/entity";
import type { VaultKeyType } from "@twin.org/vault-models";

/**
 * Class defining a vault key, version 0.
 */
@entity({ version: 0 })
export class VaultKeyV0 {
	/**
	 * The id.
	 */
	@property({ type: "string", isPrimary: true, maxLength: 255 })
	public id!: string;

	/**
	 * The type of the key e.g. Ed25519.
	 */
	@property({ type: "number" })
	public type!: VaultKeyType;

	/**
	 * The private key in base64 format.
	 */
	@property({ type: "string" })
	public privateKey!: string;

	/**
	 * The public key in base64 format.
	 */
	@property({ type: "string", optional: true })
	public publicKey?: string;
}
