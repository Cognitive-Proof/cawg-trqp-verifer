import { CAWGManifestParser, type ManifestSignal } from "./manifest_parser.js";

/** Stable adapter interface for manifest signal extraction backends. */
export interface ManifestParserAdapter {
  adapterId: string;
  parseFile(manifestPath: string): ManifestSignal;
}

/** Adapter for repository JSON fixtures and C2PA-style JSON envelopes. */
export class JsonManifestAdapter implements ManifestParserAdapter {
  readonly adapterId = "json-fixture-v1";

  parseFile(manifestPath: string): ManifestSignal {
    return CAWGManifestParser.parseFile(manifestPath);
  }
}

/** Reserved adapter boundary for binary C2PA extraction libraries. */
export class C2PABinaryManifestAdapter implements ManifestParserAdapter {
  readonly adapterId = "c2pa-binary-v1";

  parseFile(_manifestPath: string): ManifestSignal {
    throw new Error(
      "binary C2PA parsing is not bundled; install and wire a supported " +
        "C2PA extraction backend behind ManifestParserAdapter",
    );
  }
}
