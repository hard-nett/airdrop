import {
  OnRpcRequestHandler,
  OnUserInputHandler,
  UserInputEventType,
} from '@metamask/snaps-sdk';

import type { InitOutput } from '@terpnetwork/snap-n-pull';
import { initialiseWasm } from './utils/initialiseWasm';
import { gn, type GenerateNullifierParams } from './rpc/gn';

let wasm: InitOutput | null = null;

/**
 * Initialize WASM module if not already initialized
 */
async function ensureWasmInitialized(): Promise<InitOutput> {
  if (!wasm) {
    wasm = initialiseWasm();
  }
  return wasm;
}

/**
 * Handle incoming JSON-RPC requests from dApps
 *
 * Supported methods:
 * - generateNullifier: Generate note nullifier for headstash claim
 */
export const onRpcRequest: OnRpcRequestHandler = async ({
  request,
  origin,
}) => {
  // Ensure WASM is initialized
  const wasmModule = await ensureWasmInitialized();

  switch (request.method) {
    case 'generateNullifier': {
      // Validate params
      if (!request.params || typeof request.params !== 'object') {
        throw new Error('Invalid params: expected object');
      }

      const params = request.params as GenerateNullifierParams;

      // Validate required fields
      if (!params.headstashId) {
        throw new Error('Missing required field: headstashId');
      }
      if (!params.noteInputs) {
        throw new Error('Missing required field: noteInputs');
      }
      if (!params.noteInputs.recp) {
        throw new Error('Missing required field: noteInputs.recp');
      }
      if (!params.noteInputs.nd) {
        throw new Error('Missing required field: noteInputs.nd');
      }
      if (!params.noteInputs.v) {
        throw new Error('Missing required field: noteInputs.v');
      }
      if (params.noteInputs.fdi === undefined) {
        throw new Error('Missing required field: noteInputs.fdi');
      }
      if (!params.noteInputs.rho) {
        throw new Error('Missing required field: noteInputs.rho');
      }
      if (!params.noteInputs.rseed) {
        throw new Error('Missing required field: noteInputs.rseed');
      }

      // Generate nullifier
      return await gn(wasmModule, params, origin);
    }

    default:
      throw new Error(`Method not found: ${request.method}`);
  }
};