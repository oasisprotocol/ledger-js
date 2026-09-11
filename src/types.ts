/**
 * The transport surface this package needs in order to talk to a device.
 *
 * Deliberately structural rather than a nominal dependency on `Transport` from
 * `@ledgerhq/hw-transport`: `OasisApp` calls `send` and `decorateAppAPIMethods`, so
 * describing those methods lets it accept either a legacy `Transport` or a
 * `DMKTransport` built on Ledger's Device Management Kit, which replaces hw-transport
 * ahead of the September 2026 cutoff.
 *
 * A `Transport` instance satisfies this interface as-is, so this is a widening: every
 * existing caller keeps compiling unchanged.
 */
export interface Transport {
  send: (
    cla: number,
    ins: number,
    p1: number,
    p2: number,
    data?: Buffer,
    statusList?: number[],
    options?: { abortTimeoutMs?: number },
  ) => Promise<Buffer>;
  decorateAppAPIMethods: (self: Record<string, any>, methods: string[], scrambleKey: string) => void;
}

// Ledger transports throw this shape; keep it local so we do not depend on hw-transport types.
export interface TransportStatusError extends Error {
  statusCode: number;
  statusText: "UNKNOWN_ERROR";
}

export type DerivationPath = number[];

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
  console.log(successOrThrow(await app.getAddressAndPubKey_ed25519([44])).bech32_address.trim());
  console.log(successOrThrow(await app.showAddressAndPubKey_ed25519([44])).bech32_address.trim());
  console.log(successOrThrow(await app.getAddressAndPubKey_secp256k1([44])).hex_address.trim());
  console.log(successOrThrow(await app.showAddressAndPubKey_secp256k1([44])).hex_address.trim());

  const ctx = 'oasis-core/consensus'
  const msg = Buffer.from('a')
  console.log(successOrThrow(await app.sign([44], ctx, msg)).signature?.byteLength.toFixed());
}
