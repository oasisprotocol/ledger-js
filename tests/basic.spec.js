import OasisApp from "index.js";
import { serializePathv1 } from "../src/helperV1";

const context = "oasis-core/consensus: tx for chain testing";

test("check prepare chunks function", async () => {
  const serializedPath = serializePathv1([44, 123, 5, 0, 3]);
  const message = Buffer.from(
    "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq" +
      "83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
    "base64",
  );

  const chunks = OasisApp.prepareChunks(serializedPath, context, message);

  // Expect first chunk to be path
  expect(chunks[0]).toEqual(serializedPath);
  // First chunk should be path and second should have context + message so at least 2 chunks
  expect(chunks.length).toBeGreaterThan(1);
});

test("Verify prepare chunk function with empty context", async () => {
  const serializedPath = serializePathv1([44, 123, 5, 0, 3]);
  const message = Buffer.from(
    "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq" +
      "83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
    "base64",
  );
  const emptyContext = "";

  const chunks = OasisApp.prepareChunks(serializedPath, emptyContext, message);

  // First byte should be 0 (length of context)
  expect(chunks[1][0]).toEqual(0x00);
});

test("Test prepareChunks with context bigger than 255 bytes", async () => {
  const serializedPath = serializePathv1([44, 123, 5, 0, 3]);
  const message = Buffer.from(
    "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq" +
      "83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
    "base64",
  );
  const dummyContext = "A".repeat(256);

  try {
    OasisApp.prepareChunks(serializedPath, dummyContext, message);
  } catch (e) {
    expect(e).toEqual(new Error("Maximum supported context size is 255 bytes"));
  }
});
