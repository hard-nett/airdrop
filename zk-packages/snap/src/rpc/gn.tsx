import { Box, Copyable, Divider, Heading, Text } from '@metamask/snaps-sdk/jsx';
import type { InitOutput } from '@terpnetwork/snap-n-pull';
import { getSk } from '../utils/getSk';
import { generateNullifier, type NoteInputs } from '../utils/nullifier';
import { getPk } from '../utils/getPk';
import { loadCircuitKey, downloadAndCacheCircuitKey } from '../utils/circuitKeys';

/**
 * Parameters for generating a note nullifier
 */
export type GenerateNullifierParams = {
  /** The headstash contract address */
  headstashId: string;
  /** Note details */
  noteInputs: {
    /** Recipient address (hex) */
    recp: string;
    /** Denomination (e.g., "uterp") */
    nd: string;
    /** Value amount */
    v: string;
    /** Fixed denomination index (leaf position) */
    fdi: number;
    /** Randomness rho (hex) */
    rho: string;
    /** Random seed (hex) */
    rseed: string;
  };
};

/**
 * Response from nullifier generation
 */
export type GenerateNullifierResponse = {
  /** The nullifier (hex) */
  nullifier: string;
  /** The note commitment (hex) */
  commitment: string;
  /** The public key (hex) - safe to reveal */
  pk: string;
};

/**
 * Generate note nullifier (gn^2)
 *
 * This function:
 * 1. Shows a confirmation dialog to the user
 * 2. Retrieves the secret key from MetaMask (transiently)
 * 3. Generates the nullifier and commitment
 * 4. Returns only the public outputs (nullifier, commitment, pk)
 *
 * SECURITY:
 * - Secret key is NEVER stored, logged, or returned
 * - Only used transiently for cryptographic operations
 * - Only public key is included in response
 *
 * @param wasm - Initialized WASM module
 * @param params - Note inputs for nullifier generation
 * @param origin - Origin of the request (for user confirmation)
 * @returns Nullifier, commitment, and public key
 */
export async function gn(
  wasm: InitOutput,
  params: GenerateNullifierParams,
  origin: string,
): Promise<GenerateNullifierResponse> {
  // Show confirmation dialog to user
  const result = await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'confirmation',
      content: (
        <Box>
          <Heading>Generate Nullifier for Headstash Claim</Heading>
          <Divider />
          <Text>Origin: {origin}</Text>
          <Text>Headstash ID: {params.headstashId}</Text>
          <Divider />
          <Text>Note Details:</Text>
          <Text>Recipient: {params.noteInputs.recp}</Text>
          <Text>Amount: {params.noteInputs.v} {params.noteInputs.nd}</Text>
          <Text>Position: {params.noteInputs.fdi}</Text>
          <Divider />
          <Text>
            This will generate a nullifier for claiming this headstash allocation.
            Your private key will be used temporarily but never stored or revealed. 
          </Text>
          <Divider />
          <Text>
         verify @ https://headstash.terp.network/trustless
          </Text>
        </Box>
      ),
    },
  });

  if (!result) {
    throw new Error('User rejected nullifier generation');
  }

  // Load circuit verification key for this headstash (with caching)
  // This minimizes bandwidth by caching VK locally
  let vk: string | null = null;
  try {
    vk = await loadCircuitKey(params.headstashId, 'vk');
  } catch (error) {
    // VK not available - that's okay for nullifier generation
    // We only need VK for proof verification, not nullifier derivation
    console.warn(`VK not available for ${params.headstashId}:`, error);
  }

  // Retrieve secret key from MetaMask (transiently - not stored)
  const sk = await getSk();

  // Derive public key (safe to reveal)
  const pk = await getPk(sk);

  // Convert value to BigInt
  const noteInputs: NoteInputs = {
    recp: params.noteInputs.recp,
    nd: params.noteInputs.nd,
    v: BigInt(params.noteInputs.v),
    fdi: params.noteInputs.fdi,
    rho: params.noteInputs.rho,
    rseed: params.noteInputs.rseed,
  };

  // Generate nullifier and commitment
  const nullifierData = await generateNullifier(wasm, sk, noteInputs);

  // Clear the secret key from memory
  sk.fill(0);

  // Return only public data
  return {
    nullifier: nullifierData.nullifier,
    commitment: nullifierData.commitment,
    pk, // Public key - safe to reveal
    vk_cached: vk !== null, // Indicate if VK is cached for future proof generation
  };
}
