// Copyright 2026 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.

/**
 * The parts of data encrypted under a wrapped data key.
 */
export interface IDataKeyEnvelope {
	/**
	 * The prefix and wrapped data key, bound to the payload as additional authenticated data.
	 */
	header: Uint8Array;

	/**
	 * The transit ciphertext of the data key.
	 */
	wrappedKey: string;

	/**
	 * The nonce of the payload.
	 */
	nonce: Uint8Array;

	/**
	 * The encrypted payload and its authentication tag.
	 */
	payload: Uint8Array;
}
