// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to import a key.
 */
export interface IImportKeyRequest {
	/**
	 * The type of the key to be imported.
	 */
	type: string;

	/**
	 * The data of the key to be imported.
	 */
	key: string;

	/**
	 * Whether the key should be exportable.
	 */
	exportable?: boolean;

	/**
	 * Whether the key should allow plaintext backup.
	 */
	allow_plaintext_backup?: boolean;
}
