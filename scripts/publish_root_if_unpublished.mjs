// Publishes the root @cognitiveproof/cawg-trqp package itself.
//
// changeset publish never touches this package: @manypkg/get-packages
// (a changesets dependency) doesn't return the root package.json as part of
// "the workspace" when the root also declares `workspaces`, so a changeset
// naming the root package fails outright ("not in the workspace") and — once
// that entry is removed to work around it — changeset publish simply has
// nothing to say about it. This step publishes it directly, mirroring what
// changesets does for the plugin packages: skip if the local version is
// already live, publish with provenance if not.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));

const published = execFileSync("npm", ["view", pkg.name, "versions", "--json"], {
  encoding: "utf-8",
}).trim();
const versions = published ? JSON.parse(published) : [];

if (versions.includes(pkg.version)) {
  console.log(`${pkg.name}@${pkg.version} is already published on npm, skipping.`);
  process.exit(0);
}

console.log(`Publishing ${pkg.name}@${pkg.version}...`);
execFileSync("npm", ["publish", "--provenance", "--access", "public"], { stdio: "inherit" });
