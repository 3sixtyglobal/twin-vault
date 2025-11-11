// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { EntitySchemaFactory, EntitySchemaHelper } from "@twin.org/entity";
import { nameof } from "@twin.org/nameof";
import { VaultKey } from "./entities/vaultKey.js";
import { VaultSecret } from "./entities/vaultSecret.js";

/**
 * Initialize the schema for the vault connector entity storage.
 */
export function initSchema(): void {
	EntitySchemaFactory.register(nameof<VaultKey>(), () => EntitySchemaHelper.getSchema(VaultKey));
	EntitySchemaFactory.register(nameof<VaultSecret>(), () =>
		EntitySchemaHelper.getSchema(VaultSecret)
	);
}
