import { DMKTransport } from "@zondax/ledger-js";
import OasisApp from "../src/index";
import { LEGACY_TRANSPORT_DEPRECATION, resetLegacyTransportWarning } from "../src/deprecation";

function handRolledTransport() {
  return {
    send: () => Promise.resolve(Buffer.from([0x90, 0x00])),
    decorateAppAPIMethods: () => {},
  };
}

describe("legacy transport deprecation", () => {
  let warn;

  beforeEach(() => {
    // The flag is module state: another test in this process may already have tripped it.
    resetLegacyTransportWarning();
    warn = jest.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    warn.mockRestore();
  });

  test("warns when constructed over a non-DMK transport", () => {
    expect(() => new OasisApp(handRolledTransport())).not.toThrow();

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(LEGACY_TRANSPORT_DEPRECATION);
  });

  test("warns once per process, not once per app", () => {
    expect(() => new OasisApp(handRolledTransport())).not.toThrow();
    expect(() => new OasisApp(handRolledTransport())).not.toThrow();

    expect(warn).toHaveBeenCalledTimes(1);
  });

  test("stays silent over a DMKTransport", () => {
    const dmk = {
      sendApdu: () => Promise.resolve({ statusCode: Uint8Array.from([0x90, 0x00]), data: new Uint8Array() }),
    };

    expect(() => new OasisApp(new DMKTransport(dmk, "session-1"))).not.toThrow();

    expect(warn).not.toHaveBeenCalled();
  });

  test("still rejects a missing transport before warning", () => {
    expect(() => new OasisApp(undefined)).toThrow("Transport has not been defined");
    expect(warn).not.toHaveBeenCalled();
  });
});
