import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { Command } from "commander";
import { signAuditBundleFromPath } from "./attestation.js";
import { auditBundleToDict, buildAuditBundle } from "./audit.js";
import { loadManifestFixture } from "./fixture_loader.js";
import { createVerificationRequest } from "./models.js";
import { MockTRQPService } from "./mock_service.js";
import { loadProfile } from "./profile.js";
import { SnapshotStore } from "./snapshot.js";
import { TrustGateway } from "./gateway.js";
import { Verifier } from "./verifier.js";

export function main(argv: string[] = process.argv): void {
  const program = new Command();
  program
    .description("CAWG-TRQP reference verifier")
    .argument("[request_json]", "Path to verification request JSON")
    .option("--fixture <path>", "Path to CAWG/C2PA-style manifest fixture")
    .option("--authority-id <id>", "Authority id", "did:web:media-registry.example")
    .option("--profile <profile>", "Profile name or JSON file path", "standard")
    .option("--overlay <overlay>", "Overlay name or JSON file path (repeatable)", collectOverlay, [] as string[])
    .option("--policies <path>", "Policy feed path", "data/policies.json")
    .option("--snapshot <path>", "Snapshot path", "data/snapshot.json")
    .option("--trust-anchors <path>", "Trust anchors path", "data/trust_anchors.json")
    .option("--revocations <path>", "Revocation feed path", "data/revocations.json")
    .option("--policy-descriptor <path>", "Path to signed policy feed descriptor")
    .option("--revocation-descriptor <path>", "Path to signed revocation feed descriptor")
    .option("--use-gateway", "Route live policy queries through trust gateway", false)
    .option("--export-audit-bundle <path>", "Path to write audit bundle JSON")
    .option("--exported-at <timestamp>", "Deterministic timestamp override for audit bundle export")
    .option("--bundle-signing-key <path>", "Path to Ed25519 private key PEM for bundle attestation")
    .option("--bundle-key-id <keyId>", "Trust-anchor key identifier for bundle attestation")
    .allowExcessArguments(false);

  program.parse(argv);
  const opts = program.opts();
  const [requestJson] = program.args;

  const resolvedProfile = loadProfile(opts.profile, opts.overlay.length ? opts.overlay : null);

  if (opts.bundleSigningKey && !opts.bundleKeyId) {
    throw new CliError("--bundle-key-id is required when --bundle-signing-key is used");
  }
  if (opts.exportAuditBundle && resolvedProfile.controls.evidence.require_attestation && !opts.bundleSigningKey) {
    throw new CliError(
      "selected profile requires audit bundle attestation; provide --bundle-signing-key and --bundle-key-id",
    );
  }

  const root = process.cwd();
  let request;
  if (opts.fixture) {
    request = loadManifestFixture(path.join(root, opts.fixture), opts.authorityId);
  } else if (requestJson) {
    const requestData = JSON.parse(readFileSync(path.join(root, requestJson), "utf-8"));
    request = createVerificationRequest(requestData);
  } else {
    throw new CliError("Provide either request_json or --fixture");
  }

  const service =
    resolvedProfile.base_profile === "edge"
      ? null
      : new MockTRQPService(path.join(root, opts.policies), path.join(root, opts.revocations), {
          policyDescriptorPath: opts.policyDescriptor ? path.join(root, opts.policyDescriptor) : null,
          revocationDescriptorPath: opts.revocationDescriptor ? path.join(root, opts.revocationDescriptor) : null,
          trustAnchorsPath: path.join(root, opts.trustAnchors),
        });
  let snapshot: SnapshotStore | null = null;
  const gateway = opts.useGateway && service !== null ? new TrustGateway(service) : null;
  if (resolvedProfile.base_profile === "edge") {
    snapshot = new SnapshotStore(path.join(root, opts.snapshot), path.join(root, opts.trustAnchors));
  }
  const verifier = new Verifier({ service, snapshot, gateway });
  const result = verifier.verify(request, resolvedProfile);
  console.log(JSON.stringify(result, null, 2));

  if (opts.exportAuditBundle) {
    let bundle: Record<string, unknown> = auditBundleToDict(
      buildAuditBundle(request, result, {
        profile: resolvedProfile,
        useGateway: Boolean(opts.useGateway),
        exportedAt: opts.exportedAt,
        policyPath: resolvedProfile.base_profile !== "edge" ? opts.policies : null,
        revocationPath: resolvedProfile.base_profile !== "edge" ? opts.revocations : null,
        policyDescriptorPath: opts.policyDescriptor ?? null,
        revocationDescriptorPath: opts.revocationDescriptor ?? null,
        trustAnchorsPath: opts.trustAnchors,
      }),
    );
    if (opts.bundleSigningKey) {
      bundle = signAuditBundleFromPath(bundle, path.join(root, opts.bundleSigningKey), { keyId: opts.bundleKeyId });
    }
    writeFileSync(opts.exportAuditBundle, JSON.stringify(bundle, null, 2), "utf-8");
  }
}

function collectOverlay(value: string, previous: string[]): string[] {
  return [...previous, value];
}

export class CliError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliError";
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isMain) {
  try {
    main();
  } catch (err) {
    if (err instanceof CliError) {
      console.error(err.message);
      process.exitCode = 1;
    } else {
      throw err;
    }
  }
}
