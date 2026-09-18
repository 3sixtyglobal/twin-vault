// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { entity, property } from "@twin.org/entity";

/**
 * Class defining a vault secret.
 */
@entity()
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
}
