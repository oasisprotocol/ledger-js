export const CLA = 0x05;
export const CHUNK_SIZE = 250;
export const APP_KEY = "OAS";

export const INS = {
  GET_VERSION: 0x00,
  GET_ADDR_ED25519: 0x01,
  SIGN_ED25519: 0x02,
  GET_ADDR_SECP256K1: 0x04,
  SIGN_PT_ED25519: 0x05,
  SIGN_PT_SECP256K1: 0x07,
};

export const DEFAULT_HRP = "oasis";

export const PAYLOAD_TYPE = {
  INIT: 0x00,
  ADD: 0x01,
  LAST: 0x02,
};

export const P1_VALUES = {
  ONLY_RETRIEVE: 0x00,
  SHOW_ADDRESS_IN_DEVICE: 0x01,
};

const ERROR_DESCRIPTION = {
  1: "U2F: Unknown",
  2: "U2F: Bad request",
  3: "U2F: Configuration unsupported",
  4: "U2F: Device Ineligible",
  5: "U2F: Timeout",
  14: "Timeout",
  0x9000: "No errors",
  0x9001: "Device is busy",
  0x6802: "Error deriving keys",
  0x6400: "Execution Error",
  0x6700: "Wrong Length",
  0x6982: "Empty Buffer",
  0x6983: "Output buffer too small",
  0x6984: "Data is invalid",
  0x6985: "Conditions not satisfied",
  0x6986: "Transaction rejected",
  0x6a80: "Bad key handle",
  0x6b00: "Invalid P1/P2",
  0x6d00: "Instruction not supported",
  0x6e00: "Oasis app does not seem to be open",
  0x6f00: "Unknown error",
  0x6f01: "Sign/verify error",
};

/** @returns {string} */
export function errorCodeToString(statusCode) {
  if (statusCode in ERROR_DESCRIPTION) {
    return ERROR_DESCRIPTION[statusCode];
  }
  return `Unknown Status Code: ${statusCode}`;
}

/** @param {import('./types').TransportStatusError} response */
export function processErrorResponse(response) {
  // Leave non-Ledger errors as they are.
  if (!("statusCode" in response)) {
    throw response;
  }
  return {
    return_code: response.statusCode,
    error_message: errorCodeToString(response.statusCode),
  };
}

/** @param {import('./types').Transport} transport */
export async function getVersion(transport) {
  return transport.send(CLA, INS.GET_VERSION, 0, 0).then((response) => {
    const errorCodeData = response.slice(-2);
    const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

    let targetId = 0;
    if (response.length >= 9) {
      /* eslint-disable no-bitwise */
      targetId = (response[5] << 24) + (response[6] << 16) + (response[7] << 8) + (response[8] << 0);
      /* eslint-enable no-bitwise */
    }

    return {
      return_code: returnCode,
      error_message: errorCodeToString(returnCode),
      // ///
      test_mode: response[0] !== 0,
      major: response[1],
      minor: response[2],
      patch: response[3],
      device_locked: response[4] === 1,
      target_id: targetId.toString(16),
    };
  }, processErrorResponse);
}
