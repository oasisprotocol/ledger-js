/** ******************************************************************************
 *  (c) 2019 ZondaX GmbH
 *  (c) 2016-2017 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import { publicKeyv1, serializePathv1, signSendChunkv1 } from "./helperV1";
import {
  APP_KEY,
  CHUNK_SIZE,
  CLA,
  INS,
  errorCodeToString,
  getVersion,
  processErrorResponse,
  P1_VALUES,
} from "./common";

function processGetAddrEd25519Response(response) {
  const errorCodeData = response.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const pk = Buffer.from(response.slice(0, 32));
  const bech32Address = Buffer.from(response.slice(32, -2)).toString();

  return {
    bech32_address: bech32Address,
    pk,
    return_code: returnCode,
    error_message: errorCodeToString(returnCode),
  };
}

export default class OasisApp {
  constructor(transport, scrambleKey = APP_KEY) {
    if (!transport) {
      throw new Error("Transport has not been defined");
    }

    this.transport = transport;
    transport.decorateAppAPIMethods(
      this,
      ["getVersion", "sign", "getAddressAndPubKey", "appInfo", "deviceInfo"],
      scrambleKey,
    );
  }

  async serializePath(path) {
    this.versionResponse = await getVersion(this.transport);
    switch (this.versionResponse.major) {
      case 0:
      case 1:
      case 2:
        return serializePathv1(path);
      default:
        return {
          return_code: 0x6400,
          error_message: "App Version is not supported",
        };
    }
  }

  static prepareChunks(serializedPathBuffer, context, message) {
    const chunks = [];

    // First chunk (only path)
    chunks.push(serializedPathBuffer);

    const contextSizeBuffer = Buffer.from([context.length]);
    const contextBuffer = Buffer.from(context);
    const messageBuffer = Buffer.from(message);

    if (context.length > 255) {
      throw new Error("Maximum supported context size is 255 bytes");
    }

    if (contextSizeBuffer.length > 1) {
      throw new Error("Context size buffer should be exacty 1 byte");
    }

    // Now split context length + context + message into more chunks
    const buffer = Buffer.concat([contextSizeBuffer, contextBuffer, messageBuffer]);
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE;
      if (i > buffer.length) {
        end = buffer.length;
      }
      chunks.push(buffer.slice(i, end));
    }

    return chunks;
  }

  async signGetChunks(path, context, message) {
    const serializedPath = await this.serializePath(path);
    // NOTE: serializePath can return an error (not throw, but return an error!)
    // so handle that.
    if ("return_code" in serializedPath && serializedPath.return_code !== 0x9000) {
      return serializedPath;
    }

    return OasisApp.prepareChunks(serializedPath, context, message);
  }

  async getVersion() {
    this.versionResponse = await getVersion(this.transport);
    return this.versionResponse;
  }

  async appInfo() {
    return this.transport.send(0xb0, 0x01, 0, 0).then((response) => {
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      const result = {};

      let appName = "err";
      let appVersion = "err";
      let flagLen = 0;
      let flagsValue = 0;

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        result.error_message = "response format ID not recognized";
        result.return_code = 0x9001;
      } else {
        const appNameLen = response[1];
        appName = response.slice(2, 2 + appNameLen).toString("ascii");
        let idx = 2 + appNameLen;
        const appVersionLen = response[idx];
        idx += 1;
        appVersion = response.slice(idx, idx + appVersionLen).toString("ascii");
        idx += appVersionLen;
        const appFlagsLen = response[idx];
        idx += 1;
        flagLen = appFlagsLen;
        flagsValue = response[idx];
      }

      return {
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        // //
        appName,
        appVersion,
        flagLen,
        flagsValue,
        // eslint-disable-next-line no-bitwise
        flag_recovery: (flagsValue & 1) !== 0,
        // eslint-disable-next-line no-bitwise
        flag_signed_mcu_code: (flagsValue & 2) !== 0,
        // eslint-disable-next-line no-bitwise
        flag_onboarded: (flagsValue & 4) !== 0,
        // eslint-disable-next-line no-bitwise
        flag_pin_validated: (flagsValue & 128) !== 0,
      };
    }, processErrorResponse);
  }

  async deviceInfo() {
    return this.transport.send(0xe0, 0x01, 0, 0, Buffer.from([]), [0x9000, 0x6e00]).then((response) => {
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      if (returnCode === 0x6e00) {
        return {
          return_code: returnCode,
          error_message: "This command is only available in the Dashboard",
        };
      }

      const targetId = response.slice(0, 4).toString("hex");

      let pos = 4;
      const secureElementVersionLen = response[pos];
      pos += 1;
      const seVersion = response.slice(pos, pos + secureElementVersionLen).toString();
      pos += secureElementVersionLen;

      const flagsLen = response[pos];
      pos += 1;
      const flag = response.slice(pos, pos + flagsLen).toString("hex");
      pos += flagsLen;

      const mcuVersionLen = response[pos];
      pos += 1;
      // Patch issue in mcu version
      let tmp = response.slice(pos, pos + mcuVersionLen);
      if (tmp[mcuVersionLen - 1] === 0) {
        tmp = response.slice(pos, pos + mcuVersionLen - 1);
      }
      const mcuVersion = tmp.toString();

      return {
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        // //
        targetId,
        seVersion,
        flag,
        mcuVersion,
      };
    }, processErrorResponse);
  }

  async publicKey(path) {
    const serializedPath = await this.serializePath(path);
    // NOTE: serializePath can return an error (not throw, but return an error!)
    // so handle that.
    if ("return_code" in serializedPath && serializedPath.return_code !== 0x9000) {
      return serializedPath;
    }
    return publicKeyv1(this, serializedPath);
  }

  async getAddressAndPubKey(path) {
    const data = await this.serializePath(path);
    // NOTE: serializePath can return an error (not throw, but return an error!)
    // so handle that.
    if ("return_code" in data && data.return_code !== 0x9000) {
      return data;
    }
    return this.transport
      .send(CLA, INS.GET_ADDR_ED25519, P1_VALUES.ONLY_RETRIEVE, 0, data, [0x9000])
      .then(processGetAddrEd25519Response, processErrorResponse);
  }

  async showAddressAndPubKey(path) {
    const data = await this.serializePath(path);
    // NOTE: serializePath can return an error (not throw, but return an error!)
    // so handle that.
    if ("return_code" in data && data.return_code !== 0x9000) {
      return data;
    }
    return this.transport
      .send(CLA, INS.GET_ADDR_ED25519, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, data, [0x9000])
      .then(processGetAddrEd25519Response, processErrorResponse);
  }

  async signSendChunk(chunkIdx, chunkNum, chunk) {
    switch (this.versionResponse.major) {
      case 0:
      case 1:
      case 2:
        return signSendChunkv1(this, chunkIdx, chunkNum, chunk);
      default:
        return {
          return_code: 0x6400,
          error_message: "App Version is not supported",
        };
    }
  }

  async sign(path, context, message) {
    const chunks = await this.signGetChunks(path, context, message);
    // NOTE: signGetChunks can return an error (not throw, but return an error!)
    // so handle that.
    if ("return_code" in chunks && chunks.return_code !== 0x9000) {
      return chunks;
    }

    return this.signSendChunk(1, chunks.length, chunks[0]).then(async (response) => {
      if (response.return_code !== 0x9000) {
        return response;
      }
      let result = {
        return_code: response.return_code,
        error_message: response.error_message,
        signature: null,
      };

      for (let i = 1; i < chunks.length; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        result = await this.signSendChunk(1 + i, chunks.length, chunks[i]);
        if (result.return_code !== 0x9000) {
          break;
        }
      }

      return {
        return_code: result.return_code,
        error_message: result.error_message,
        // ///
        signature: result.signature,
      };
    }, processErrorResponse);
  }
}
