/**
 * Circuit key management for headstash proof generation
 *
 * This module handles loading and caching of circuit proving/verification keys
 * for different headstash instances. Keys are cached locally to minimize bandwidth.
 *
 * ## Architecture
 *
 * 1. **Static Files**: Circuit keys bundled with snap (snap.manifest.json)
 * 2. **Dynamic Download**: Download keys from headstash-api if not bundled
 * 3. **Local Caching**: Cache downloaded keys in snap storage
 *
 * ## Key Types
 *
 * - **Verification Key (VK)**: Used to verify proofs (smaller, ~1-2KB)
 * - **Proving Key (PK)**: Used to generate proofs (larger, ~100MB)
 *
 * For bandwidth optimization, we:
 * - Bundle common VKs with the snap
 * - Download PKs on-demand
 * - Cache both in snap storage by headstash ID
 */

/**
 * Circuit key metadata
 */
export type CircuitKeyMetadata = {
  headstashId: string;
  vkPath?: string; // Path to static VK file
  pkPath?: string; // Path to static PK file
  vkUrl?: string; // URL to download VK
  pkUrl?: string; // URL to download PK
  vkHash?: string; // SHA256 hash for verification
  pkHash?: string; // SHA256 hash for verification
};

/**
 * Load verification key for a headstash instance
 *
 * Priority order:
 * 1. Check snap storage (cached from previous download)
 * 2. Load from static files (bundled with snap)
 * 3. Download from headstash-api
 *
 * @param headstashId - Contract address of the headstash
 * @returns Verification key as hex string
 */
export async function loadVerificationKey(
  headstashId: string,
): Promise<string> {
  // 1. Check cache first
  const cached = await loadCachedKey(headstashId, 'vk');
  if (cached) {
    return cached;
  }

  // 2. Try loading from static files
  const staticKey = await loadStaticVK(headstashId);
  if (staticKey) {
    // Cache it for next time
    await cacheKey(headstashId, 'vk', staticKey);
    return staticKey;
  }

  // 3. Download from API
  const downloaded = await downloadVerificationKey(headstashId);
  await cacheKey(headstashId, 'vk', downloaded);
  return downloaded;
}

/**
 * Load proving key for a headstash instance
 *
 * Proving keys are much larger (~100MB), so we:
 * - Never bundle them with the snap
 * - Download on-demand
 * - Cache aggressively
 *
 * @param headstashId - Contract address of the headstash
 * @returns Proving key as hex string
 */
export async function loadProvingKey(headstashId: string): Promise<string> {
  // 1. Check cache first (proving keys are large, caching is critical)
  const cached = await loadCachedKey(headstashId, 'pk');
  if (cached) {
    return cached;
  }

  // 2. Download from API (no static files for PKs due to size)
  const downloaded = await downloadProvingKey(headstashId);
  await cacheKey(headstashId, 'pk', downloaded);
  return downloaded;
}

/**
 * Load static verification key from bundled files
 *
 * This uses snap_getFile to load VK files that were included
 * in the snap bundle via snap.manifest.json.
 *
 * @param headstashId - Contract address
 * @returns VK hex string or null if not found
 */
async function loadStaticVK(headstashId: string): Promise<string | null> {
  try {
    // Map headstash IDs to static file paths
    // This would be configured per deployment
    const vkPath = getStaticVKPath(headstashId);
    if (!vkPath) {
      return null;
    }

    // Load from static files using snap_getFile
    const contents = await snap.request({
      method: 'snap_getFile',
      params: {
        path: vkPath,
        encoding: 'hex',
      },
    });

    return contents;
  } catch (error) {
    // Static file not found, that's okay
    return null;
  }
}

/**
 * Download verification key from headstash-api
 *
 * @param headstashId - Contract address
 * @returns VK hex string
 */
async function downloadVerificationKey(headstashId: string): Promise<string> {
  // TODO: Implement actual API call
  // For now, throw to indicate not implemented
  throw new Error(`VK download not yet implemented for ${headstashId}`);

  // Example implementation:
  // const response = await fetch(
  //   `https://headstash-api.terp.network/vk/${headstashId}`,
  // );
  // const vkHex = await response.text();
  // return vkHex;
}

/**
 * Download proving key from headstash-api
 *
 * WARNING: Proving keys are very large (~100MB). This may take time.
 *
 * @param headstashId - Contract address
 * @returns PK hex string
 */
async function downloadProvingKey(headstashId: string): Promise<string> {
  // TODO: Implement actual API call with progress indication
  throw new Error(`PK download not yet implemented for ${headstashId}`);

  // Example implementation with chunked download:
  // const response = await fetch(
  //   `https://headstash-api.terp.network/pk/${headstashId}`,
  // );
  // const reader = response.body?.getReader();
  // // ... stream chunks and show progress
  // return pkHex;
}

/**
 * Load cached key from snap storage
 *
 * @param headstashId - Contract address
 * @param keyType - 'vk' or 'pk'
 * @returns Cached key hex string or null if not found
 */
async function loadCachedKey(
  headstashId: string,
  keyType: 'vk' | 'pk',
): Promise<string | null> {
  try {
    const state = await snap.request({
      method: 'snap_manageState',
      params: { operation: 'get' },
    });

    const cacheKey = `circuit_${keyType}_${headstashId}`;
    return (state as any)?.[cacheKey] || null;
  } catch (error) {
    return null;
  }
}

/**
 * Cache key in snap storage
 *
 * @param headstashId - Contract address
 * @param keyType - 'vk' or 'pk'
 * @param keyData - Key data as hex string
 */
async function cacheKey(
  headstashId: string,
  keyType: 'vk' | 'pk',
  keyData: string,
): Promise<void> {
  const state = (await snap.request({
    method: 'snap_manageState',
    params: { operation: 'get' },
  })) || {};

  const cacheKey = `circuit_${keyType}_${headstashId}`;

  await snap.request({
    method: 'snap_manageState',
    params: {
      operation: 'update',
      newState: {
        ...state,
        [cacheKey]: keyData,
      },
    },
  });
}

/**
 * Get static VK file path for a headstash ID
 *
 * This maps known headstash instances to their bundled VK files.
 * Update this mapping when deploying new headstash instances.
 *
 * @param headstashId - Contract address
 * @returns Path to static file or null
 */
function getStaticVKPath(headstashId: string): string | null {
  // Map of known headstash IDs to static VK files
  // These would be configured during snap deployment
  const staticVKMap: Record<string, string> = {
    // Example:
    // 'terp1contract123': './files/circuit-vk-v1.bin',
    // 'terp1contract456': './files/circuit-vk-v2.bin',
  };

  return staticVKMap[headstashId] || null;
}

/**
 * Clear all cached circuit keys (for testing/debugging)
 */
export async function clearCircuitKeyCache(): Promise<void> {
  const state = (await snap.request({
    method: 'snap_manageState',
    params: { operation: 'get' },
  })) || {};

  // Remove all circuit_* keys
  const newState = Object.keys(state).reduce((acc, key) => {
    if (!key.startsWith('circuit_')) {
      acc[key] = state[key];
    }
    return acc;
  }, {} as Record<string, any>);

  await snap.request({
    method: 'snap_manageState',
    params: {
      operation: 'update',
      newState,
    },
  });
}

/**
 * Download and cache circuit key from API for a headstash
 *
 * This is the main entry point for ensuring circuit keys are available.
 * It checks cache first, then downloads if needed.
 *
 * @param headstashId - Contract address
 * @param keyType - 'vk' or 'pk'
 * @returns Hex-encoded circuit key
 */
export async function downloadAndCacheCircuitKey(
  headstashId: string,
  keyType: 'vk' | 'pk',
): Promise<string> {
  if (keyType === 'vk') {
    return loadVerificationKey(headstashId);
  } else {
    return loadProvingKey(headstashId);
  }
}

/**
 * Load a circuit key (VK or PK) for a headstash
 *
 * Convenience wrapper that handles caching automatically.
 *
 * @param headstashId - Contract address
 * @param keyType - 'vk' or 'pk'
 * @returns Hex-encoded circuit key
 */
export async function loadCircuitKey(
  headstashId: string,
  keyType: 'vk' | 'pk',
): Promise<string> {
  return downloadAndCacheCircuitKey(headstashId, keyType);
}
