import { writeFileSync } from "node:fs";
import { Command } from "commander";
import { signAuditBundleFromPath } from "../src/attestation.js";
import { loadJson } from "../src/validation.js";

const program = new Command();
program
  .description("Sign a CAWG-TRQP audit bundle with Ed25519")
  .argument("<bundle_json>", "Path to unsigned audit bundle JSON")
  .argument("<private_key>", "Path to Ed25519 private key PEM")
  .requiredOption("--key-id <keyId>", "Trust-anchor key identifier")
  .option("--output <path>", "Output path. Defaults to in-place write")
  .parse(process.argv);

const [bundleJson, privateKey] = program.args;
const opts = program.opts();

const bundle = loadJson(bundleJson);
const signedBundle = signAuditBundleFromPath(bundle, privateKey, { keyId: opts.keyId });
const outputPath = opts.output ?? bundleJson;
writeFileSync(outputPath, JSON.stringify(signedBundle, null, 2) + "\n", "utf-8");
