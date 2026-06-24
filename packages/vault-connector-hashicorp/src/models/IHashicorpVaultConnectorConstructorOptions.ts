// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IHashicorpVaultConnectorConfig } from "./IHashicorpVaultConnectorConfig.js";

/**
 * Options for the hashicorp vault connector constructor.
 */
export interface IHashicorpVaultConnectorConstructorOptions {
	/**
	 * The hashicorp vault connector configuration.
	 */
	config: IHashicorpVaultConnectorConfig;
}
