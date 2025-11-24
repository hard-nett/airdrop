import {
  OnRpcRequestHandler,
  OnUserInputHandler,
  UserInputEventType,
} from '@metamask/snaps-sdk';

import { InitOutput } from '@terpnetwork/webzjs-keys';
import { initialiseWasm } from './utils/initialiseWasm';
import { gn } from './rpc/gn';

let wasm: InitOutput;

export const onRpcRequest: OnRpcRequestHandler = async ({ request, origin }) => {}