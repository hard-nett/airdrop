import type { InitOutput, initSync } from '@terpnetwork/snap-n-pull';
import wasmDataBase64 from '@terpnetwork/snap_n_pull.wasm';

export function initialiseWasm(): InitOutput {
  const base64String = wasmDataBase64 as unknown as string;
  // Check if the imported data is a data URL
  const base64Formatted = base64String.startsWith('data:')
    ? base64String.split(',')[1]
    : base64String;

  if (!base64Formatted) {
    throw new Error('Invalid WASM data');
  }

  const wasmData = Buffer.from(base64Formatted, 'base64');
  return initSync({ module: wasmData });
}
