import { CLA, errorCodeToString, INS, PAYLOAD_TYPE, processErrorResponse } from "./common";

export function serializePathv1(path) {
  if (!path || path.length !== 5) {
    throw new Error("Invalid path.");
  }

  const buf = Buffer.alloc(20);
  buf.writeUInt32LE(0x80000000 + path[0], 0);
  buf.writeUInt32LE(0x80000000 + path[1], 4);
  buf.writeUInt32LE(0x80000000 + path[2], 8);
  buf.writeUInt32LE(path[3], 12);
  buf.writeUInt32LE(path[4], 16);

  return buf;
}

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
