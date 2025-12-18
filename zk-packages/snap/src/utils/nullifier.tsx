/**
 * Nullifier generation utilities
 *
 * This module provides functions to generate note nullifiers and commitments
 * using the wasm-bindgen exports from snap-n-pull.
 *
 * SECURITY PRINCIPLE:
 * - Secret key (esk) is only used transiently during computation
 * - Never stored, logged, or transmitted
 * - Only public keys and nullifiers are returned/stored
 */

import type { InitOutput } from '@terpnetwork/snap-n-pull';

/**
 * Note data required for nullifier generation
 */
export interface NoteInputs {
  /** Recipient address (32 bytes hex) */
  recp: string;
  /** Note denomination (e.g., "uterp") */
  nd: string;
  /** Note value amount */
  v: bigint;
  /** Fixed denomination index (leaf position in merkle tree) */
  fdi: number;
  /** Randomness value rho (32 bytes hex) */
  rho: string;
  /** Random seed for note (32 bytes hex) */
  rseed: string;
}

/**
 * Generated nullifier data
 */
export interface NullifierData {
  /** The nullifier (32 bytes hex) */
  nullifier: string;
  /** The note commitment (32 bytes hex) */
  commitment: string;
  /** The nullifier deriving key (32 bytes hex) */
  nk: string;
}

/**
 * Generate nullifier and commitment for a note
 *
 * This function:
 * 1. Takes the secret key (transiently, never stored)
 * 2. Derives the nullifier key (nk) from esk and rho
 * 3. Generates the nullifier and note commitment
 * 4. Returns the cryptographic values needed for claiming
 *
 * The secret key is used only during this computation and is not retained.
 *
 * @param wasm - The initialized WASM module
 * @param esk - Secret key as Uint8Array (32 bytes) - NEVER STORED
 * @param noteInputs - Public inputs for the note
 * @returns Nullifier, commitment, and nullifier key
 */
export async function generateNullifier(
  wasm: InitOutput,
  esk: Uint8Array,
  noteInputs: NoteInputs,
): Promise<NullifierData> {
  // Convert esk to hex for WASM (this is transient, not stored)
  const eskHex = Buffer.from(esk).toString('hex');

  // Use the HeadstashWallet from WASM to generate note data
  // This follows the same pattern as the Rust implementation in
  // zk-crates/snap-n-pull/src/wallet/wallet.rs:generate_note_data

  // Import the WebWallet class from WASM
  const { WebWallet } = wasm;

  // Create a temporary wallet instance (in-memory only)
  // We use "test" network for nullifier generation (network doesn't affect crypto)
  const wallet = await WebWallet.new(
    'test',
    'http://localhost:8080', // Dummy URL, not used for nullifier generation
    null,
    null,
  );

  // Store the note to generate nullifier and commitment
  // This calls the Rust generate_note_data function internally
  await wallet.gen_claim(
    'temp_headstash_id', // Temporary ID, only used for this operation
    eskHex,
    noteInputs.rho,
    noteInputs.fdi,
    noteInputs.recp,
    noteInputs.v.toString(),
    noteInputs.nd,
    noteInputs.rseed,
  );

  // Retrieve the generated note data
  const notesJson = await wallet.list_unspent_notes('temp_headstash_id');
  const notes = JSON.parse(notesJson);

  if (notes.length === 0) {
    throw new Error('Failed to generate nullifier');
  }

  const note = notes[0];

  // Extract the nullifier data
  // Note: We're returning the nullifier key (nk) which is derived from esk+rho,
  // but we're NOT returning esk itself
  return {
    nullifier: note.nullifier,
    commitment: note.commitment,
    nk: note.nk || '', // Nullifier key (safe to store/reveal)
  };
}

/**
 * Derive public key from secret key
 *
 * This uses the WASM secp256k1 implementation to derive the public key.
 * The public key is safe to reveal and store.
 *
 * @param esk - Secret key as Uint8Array (32 bytes)
 * @returns Public key as hex string (33 bytes compressed)
 */
export function derivePk(esk: Uint8Array): string {
  // Use noble-secp256k1 for key derivation
  // This is a pure JS implementation, lightweight and secure
  const { secp256k1 } = require('@noble/curves/secp256k1');

  // Derive compressed public key
  const pk = secp256k1.getPublicKey(esk, true);

  return Buffer.from(pk).toString('hex');
}
