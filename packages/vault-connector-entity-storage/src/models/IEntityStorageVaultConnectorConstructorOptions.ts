// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import type { IEntityStorageVaultConnectorConfig } from "./IEntityStorageVaultConnectorConfig.js";

/**
 * Options for the entity storage vault connector constructor.
 */
export interface IEntityStorageVaultConnectorConstructorOptions {
	/**
	 * The vault key entity storage connector type.
	 * @default vault-key
	 */
	vaultKeyEntityStorageType?: string;

	/**
	 * The vault secret entity storage connector type.
	 * @default vault-secret
	 */
	vaultSecretEntityStorageType?: string;

	/**
	 * The entity storage vault connector configuration.
	 */
	config?: IEntityStorageVaultConnectorConfig;
}
