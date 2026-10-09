// Copyright 2024 IOTA Stiftung.
// SPDX-License-Identifier: Apache-2.0.
import { Factory } from "@3sixty/core";
import type { IVaultConnector } from "../models/IVaultConnector.js";

/**
 * Factory for creating vault connectors.
 */
// eslint-disable-next-line @typescript-eslint/naming-convention
export const VaultConnectorFactory = Factory.createFactory<IVaultConnector>("vault");
