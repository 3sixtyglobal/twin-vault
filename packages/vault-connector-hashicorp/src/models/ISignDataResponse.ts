// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * Represents the response received after signing the data.
 */
export interface ISignDataResponse {
	/**
	 * The signature of the data, prefixed with the vault version token.
	 */
	signature: string;
}
