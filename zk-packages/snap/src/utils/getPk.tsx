/**
 * Derive the public key from the secret key
 *
 * This function derives the secp256k1 public key from the secret key.
 * The public key is used for verification and address derivation but never
 * reveals the private key.
 *
 * @param sk - The secret key as Uint8Array (32 bytes)
 * @returns The compressed public key as hex string (33 bytes, 66 hex chars)
 */
export async function getPk(sk: Uint8Array): Promise<string> {
  // Use secp256k1 to derive public key
  const { secp256k1 } = await import('@noble/curves/secp256k1');

  // Derive public key (compressed format)
  const publicKey = secp256k1.getPublicKey(sk, true);

  // Return as hex string
  return Buffer.from(publicKey).toString('hex');
}

/**
 * Derive the Ethereum-style address from public key
 *
 * This follows the Ethereum EIP-55 address derivation:
 * 1. Serialize uncompressed public key (65 bytes)
 * 2. Hash with Keccak256
 * 3. Take last 20 bytes
 *
 * @param pk - The compressed public key as hex string
 * @returns The Ethereum-style address (0x-prefixed, 40 hex chars for 20 bytes)
 */
export async function pkToAddress(pk: string): Promise<string> {
  const { secp256k1 } = await import('@noble/curves/secp256k1');
  const { keccak_256 } = await import('@noble/hashes/sha3');

  // Convert compressed public key to bytes
  const pkBytes = Buffer.from(pk, 'hex');

  // Get uncompressed public key (remove 0x04 prefix for hashing)
  const uncompressed = secp256k1.ProjectivePoint.fromHex(pkBytes).toRawBytes(false);

  // Hash the uncompressed public key (excluding the 0x04 prefix byte)
  const hash = keccak_256(uncompressed.slice(1));

  // Take last 20 bytes
  const address = hash.slice(-20);

  // Return as 0x-prefixed hex string
  return '0x' + Buffer.from(address).toString('hex');
}
