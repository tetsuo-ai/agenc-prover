import assert from "node:assert/strict";
import test from "node:test";
import { Keypair } from "@solana/web3.js";
import { buildPrivatePayload } from "./devnet-preflight.js";

test("buildPrivatePayload is deterministic and preserves expected lengths", () => {
  const taskPda = Keypair.generate().publicKey;
  const authority = Keypair.generate().publicKey;

  const first = buildPrivatePayload(taskPda, authority);
  const second = buildPrivatePayload(taskPda, authority);

  assert.deepEqual(first.sealBytes, second.sealBytes);
  assert.deepEqual(first.journal, second.journal);
  assert.deepEqual(first.imageId, second.imageId);
  assert.deepEqual(first.bindingSeed, second.bindingSeed);
  assert.deepEqual(first.nullifierSeed, second.nullifierSeed);

  assert.equal(first.sealBytes.length, 260);
  assert.equal(first.journal.length, 192);
  assert.equal(first.imageId.length, 32);
  assert.equal(first.bindingSeed.length, 32);
  assert.equal(first.nullifierSeed.length, 32);
});
