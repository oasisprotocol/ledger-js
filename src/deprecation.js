export const LEGACY_TRANSPORT_DEPRECATION =
  "[@oasisprotocol/ledger] Passing a transport other than DMKTransport to OasisApp is deprecated and will be " +
  "rejected in the next major version. Ledger deprecated @ledgerhq/hw-transport in favour of the Device " +
  "Management Kit: wrap a DMK session instead, e.g. new OasisApp(new DMKTransport(dmk, sessionId)), with " +
  "DMKTransport from @zondax/ledger-js.";

let legacyTransportWarned = false;

/**
 * Logs {@link LEGACY_TRANSPORT_DEPRECATION} the first time it is called, and never again.
 *
 * Once per process rather than once per app: wallets construct an app per request, and a
 * warning on every construction would bury everything else in their logs.
 */
export function warnLegacyTransport() {
  if (legacyTransportWarned) {
    return;
  }
  legacyTransportWarned = true;
  // eslint-disable-next-line no-console
  console.warn(LEGACY_TRANSPORT_DEPRECATION);
}

/**
 * Forgets that the warning was logged. Test-only: not exported from the package index.
 */
export function resetLegacyTransportWarning() {
  legacyTransportWarned = false;
}
