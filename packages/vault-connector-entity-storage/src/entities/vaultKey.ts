// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@3sixty/entity";
import type { VaultKeyType } from "@3sixty/vault-models";

/**
 * Class defining a vault key.
 */
@entity({ version: 1 })
export class VaultKey {
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

	/**
	 * The date the key was created, in ISO 8601 format.
	 */
	@property({ type: "string", format: "date-time", optional: true })
	public dateCreated?: string;

	/**
	 * The date the key was last modified, in ISO 8601 format.
	 */
	@property({ type: "string", format: "date-time", optional: true })
	public dateModified?: string;
}
