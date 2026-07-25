import { Ajv2020 } from "ajv/dist/2020.js";
import * as ajvFormatsModule from "ajv-formats";

// ajv-formats ships a CJS default export; NodeNext resolution doesn't line up
// the .d.ts default-export shape with the runtime interop shim, so unwrap manually.
const addFormats = (ajvFormatsModule as unknown as { default: (ajv: Ajv2020) => unknown }).default;

export function createAjv(): Ajv2020 {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv;
}
