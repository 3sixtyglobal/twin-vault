// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { EntitySchemaFactory, EntitySchemaHelper } from "@twin.org/entity";
import { nameof } from "@twin.org/nameof";
import { VaultKey } from "./entities/vaultKey.js";
import { VaultKeyV0 } from "./entities/vaultKeyV0.js";
import { VaultSecret } from "./entities/vaultSecret.js";
import { VaultSecretV0 } from "./entities/vaultSecretV0.js";

/**
 * Initialize the schema for the vault connector entity storage.
 */
export function initSchema(): void {
	EntitySchemaFactory.register(nameof<VaultKey>(), () => EntitySchemaHelper.getSchema(VaultKey));
	EntitySchemaFactory.register(nameof<VaultKeyV0>(), () =>
		EntitySchemaHelper.getSchema(VaultKeyV0)
	);
	EntitySchemaFactory.register(nameof<VaultSecret>(), () =>
		EntitySchemaHelper.getSchema(VaultSecret)
	);
	EntitySchemaFactory.register(nameof<VaultSecretV0>(), () =>
		EntitySchemaHelper.getSchema(VaultSecretV0)
	);
}
