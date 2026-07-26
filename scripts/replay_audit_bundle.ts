import { Command } from "commander";
import { replayAuditBundle } from "../src/replay.js";
import { loadJson } from "../src/validation.js";

const program = new Command();
program
  .description("Replay a CAWG-TRQP audit bundle against pinned or supplied policy data")
  .argument("<bundle_json>", "Path to audit bundle JSON")
  .option("--policies <path>", "Path to policy data JSON. Defaults to replay_inputs.policy_feed.policy_source")
  .option("--revocations <path>", "Path to revocation data JSON. Defaults to replay_inputs.policy_feed.revocation_source")
  .option("--trusted-root <path>", "Directory boundary for replay bundle referenced files", ".")
  .parse(process.argv);

const [bundleJson] = program.args;
const opts = program.opts();

const bundle = loadJson(bundleJson);
const report = await replayAuditBundle(bundle, {
  policyPath: opts.policies ?? null,
  revocationPath: opts.revocations ?? null,
  trustedRoot: opts.trustedRoot,
});
console.log(
  JSON.stringify(
    {
      matches: report.matches,
      differences: report.differences,
      policy_sources: report.policy_sources,
      replayed_result: report.replayed_result,
    },
    null,
    2,
  ),
);
if (!report.matches) {
  process.exit(1);
}
