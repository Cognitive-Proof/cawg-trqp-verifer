import { readFileSync, writeFileSync } from "node:fs";
import { createPrivateKey, sign } from "node:crypto";
import { Command } from "commander";
import { SnapshotStore } from "../src/snapshot.js";

const program = new Command();
program
  .description("Sign a CAWG-TRQP offline snapshot with Ed25519")
  .argument("<snapshot>", "Path to unsigned snapshot JSON")
  .argument("<private_key>", "Path to Ed25519 private key PEM")
  .requiredOption("--key-id <keyId>", "Trust-anchor key identifier")
  .option("--output <path>", "Output path. Defaults to in-place write")
  .parse(process.argv);

const [snapshotPath, privateKeyPath] = program.args;
const opts = program.opts();

const data = JSON.parse(readFileSync(snapshotPath, "utf-8"));
delete data.signature;

const privateKey = createPrivateKey({ key: readFileSync(privateKeyPath), format: "pem" });
const payload = SnapshotStore.canonicalPayload(data);
const signature = sign(null, payload, privateKey);
data.signature = {
  algorithm: "Ed25519",
  key_id: opts.keyId,
  value: signature.toString("base64"),
};

const outputPath = opts.output ?? snapshotPath;
writeFileSync(outputPath, JSON.stringify(data, null, 2) + "\n", "utf-8");
