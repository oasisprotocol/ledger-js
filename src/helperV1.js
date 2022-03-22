import { CLA, errorCodeToString, INS, PAYLOAD_TYPE, processErrorResponse } from "./common";

/** @param {import('./types').DerivationPath} path */
export function serializePathv1(path) {
  // length 3: ADR 8 derivation path
  // length 5: Legacy derivation path
  if (!path || (path.length !== 3 && path.length !== 5)) {
    throw new Error("Invalid path.");
  }

  /* eslint no-bitwise: "off", no-plusplus: "off" */
  const buf = Buffer.alloc(path.length * 4);
  for (let i = 0; i < path.length; i++) {
    // Harden all path components by ORing them with 0x80000000.
    const hardened = (0x80000000 | path[i]) >>> 0;
    buf.writeUInt32LE(hardened, i * 4);
  }

  return buf;
}

/** @param {import('./types').App} app */
export async function signSendChunkv1(app, chunkIdx, chunkNum, chunk) {
  let payloadType = PAYLOAD_TYPE.ADD;
  if (chunkIdx === 1) {
    payloadType = PAYLOAD_TYPE.INIT;
  }
  if (chunkIdx === chunkNum) {
    payloadType = PAYLOAD_TYPE.LAST;
  }
  return app.transport
    .send(CLA, INS.SIGN_ED25519, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
    .then((response) => {
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
      let errorMessage = errorCodeToString(returnCode);

      if (returnCode === 0x6a80 || returnCode === 0x6984) {
        errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
      }

      let signature = null;
      if (response.length > 2) {
        signature = response.slice(0, response.length - 2);
      }

      return {
        signature,
        return_code: returnCode,
        error_message: errorMessage,
      };
    }, processErrorResponse);
}

/** @param {import('./types').App} app */
export async function publicKeyv1(app, data) {
  return app.transport.send(CLA, INS.GET_ADDR_ED25519, 0, 0, data, [0x9000]).then((response) => {
    const errorCodeData = response.slice(-2);
    const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

    return {
      pk: Buffer.from(response.slice(0, 32)),
      return_code: returnCode,
      error_message: errorCodeToString(returnCode),
    };
  }, processErrorResponse);
}
