import { existsSync } from "node:fs";
import { Command } from "commander";
import { HTTPTRQPService } from "../src/http_service.js";
import { MockTRQPService } from "../src/mock_service.js";

const program = new Command();
program
  .description("Start CAWG-TRQP HTTP service")
  .option("--policy-path <path>", "Path to policies.json", "data/policies.json")
  .option("--revocation-path <path>", "Path to revocations.json (optional)", "data/revocations.json")
  .option("--host <host>", "Bind address", "127.0.0.1")
  .option("--port <port>", "Bind port", "5000")
  .parse(process.argv);

const opts = program.opts();

if (!existsSync(opts.policyPath)) {
  console.error(`Error: Policy file not found: ${opts.policyPath}`);
  process.exit(1);
}

let revocationPath: string | null = null;
if (opts.revocationPath) {
  if (!existsSync(opts.revocationPath)) {
    console.warn(`Warning: Revocation file not found: ${opts.revocationPath}`);
  } else {
    revocationPath = opts.revocationPath;
  }
}

console.log("Starting TRQP HTTP service...");
console.log(`  Policy path: ${opts.policyPath}`);
if (revocationPath) {
  console.log(`  Revocation path: ${revocationPath}`);
}
console.log(`  Address: http://${opts.host}:${opts.port}`);
console.log();
console.log("Endpoints:");
console.log("  POST /trqp/authorization");
console.log("  POST /trqp/recognition");
console.log("  GET /health");
console.log();

const policyService = new MockTRQPService(opts.policyPath, revocationPath);
const service = new HTTPTRQPService(policyService);
service.run(opts.host, Number(opts.port));
