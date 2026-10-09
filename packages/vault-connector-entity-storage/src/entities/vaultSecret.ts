// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@3sixty/entity";

/**
 * Class defining a vault secret.
 */
@entity({ version: 1 })
export class VaultSecret {
	/**
	 * The id.
	 */
	@property({ type: "string", isPrimary: true, maxLength: 255 })
	public id!: string;

	/**
	 * The data for the secret.
	 */
	@property({ type: "object" })
	public data!: unknown;

	/**
	 * The date the secret was created, in ISO 8601 format.
	 */
	@property({ type: "string", format: "date-time", optional: true })
	public dateCreated?: string;

	/**
	 * The date the secret was last modified, in ISO 8601 format.
	 */
	@property({ type: "string", format: "date-time", optional: true })
	public dateModified?: string;
}
