/**
 * Retrieve the secret key from MetaMask Snap
 *
 * This function requests entropy from MetaMask using BIP-32 derivation.
 * The secret key is NEVER stored or revealed - only used transiently for
 * cryptographic operations (nullifier generation, signing).
 *
 * SECURITY:
 * - Private key is only accessed when needed for specific operations
 * - Never logged, stored, or transmitted
 * - Only the public key is ever revealed in spent note records
 *
 * Uses snap_getBip32Entropy as per:
 * https://docs.metamask.io/snaps/reference/snaps-api/#snap_getbip32entropy
 *
 * @returns The 32-byte secret key as Uint8Array
 */
export async function getSk(): Promise<Uint8Array> {
  // Request BIP-32 entropy from MetaMask Snap
  // Path: m/44'/133'/0'/0'/0' (Zcash coin type as placeholder for Terp Network)
  const entropyResult = await snap.request({
    method: 'snap_getBip32Entropy',
    params: {
      path: ['m', "44'", "133'", "0'", "0'", "0'"],
      curve: 'secp256k1',
    },
  });

  // Extract the private key from the entropy result
  // The privateKey is returned as a hex string (without 0x prefix)
  const privateKeyHex = entropyResult.privateKey;

  // Convert hex string to Uint8Array (32 bytes)
  const privateKeyBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    privateKeyBytes[i] = parseInt(privateKeyHex.substr(i * 2, 2), 16);
  }

  return privateKeyBytes;
}
