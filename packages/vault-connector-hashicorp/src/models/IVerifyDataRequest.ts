// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Request to verify a signature.
 */
export interface IVerifyDataRequest {
	/**
	 * The original data that was signed, encoded in Base64.
	 */
	input: string;

	/**
	 * The signature to be verified, prefixed with the vault version token.
	 */
	signature: string;
}
