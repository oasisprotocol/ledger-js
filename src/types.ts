import type Transport from "@ledgerhq/hw-transport";

export type { Transport };

// @ledgerhq/hw-transport has an awful TransportStatusError type
export interface TransportStatusError extends Error {
  statusCode: number;
  statusText: "UNKNOWN_ERROR";
}

export type DerivationPath = number[] | string;

export interface App {
  transport: Transport;
}

export type Response<T> =
  T & {
    return_code: number;
    error_message: string;
  } | {
    return_code: number;
    error_message: string;
  };

export type AsyncResponse<T> = Promise<Response<T>>;

/** Ensures good inferred types  */
async function typeOnlyTest() {
  const { default: OasisApp, successOrThrow } = await import('./index');
  const { default: TransportWebUSB } = await import('@ledgerhq/hw-transport-webusb');
  const app = new OasisApp(await TransportWebUSB.create());
  console.log(successOrThrow(await app.getVersion()).major.toFixed());
  console.log(successOrThrow(await app.appInfo()).appName.trim());
  console.log(successOrThrow(await app.deviceInfo()).mcuVersion.trim());
  console.log(successOrThrow(await app.publicKey([44])).pk.byteLength.toFixed());
  console.log(successOrThrow(await app.getAddressAndPubKey([44])).bech32_address.trim());
  console.log(successOrThrow(await app.showAddressAndPubKey([44])).bech32_address.trim());

  const ctx = 'oasis-core/consensus'
  const msg = Buffer.from('a')
  console.log(successOrThrow(await app.sign([44], ctx, msg)).signature?.byteLength.toFixed());
}
