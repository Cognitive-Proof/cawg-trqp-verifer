import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { TrustGateway } from "../src/gateway.js";
import { createVerificationRequest, type VerificationRequest } from "../src/models.js";
import { MockTRQPService } from "../src/mock_service.js";
import { Verifier } from "../src/verifier.js";

describe("gateway routes", () => {
  it("routes multi-authority requests deterministically", async () => {
    const routes = {
      "did:web:media-registry.example": {
        service: new MockTRQPService("data/policies_multi_authority.json"),
        route_label: "route:media-india",
      },
      "did:web:coalition-registry.example": {
        service: new MockTRQPService("data/policies_multi_authority.json"),
        route_label: "route:coalition-eu",
      },
    };
    const gateway = new TrustGateway(null, { gatewayId: "gateway:mesh", authorityRoutes: routes });
    const verifier = new Verifier({ gateway });

    const vectors = JSON.parse(readFileSync("examples/interoperability_vector_multi_authority.json", "utf-8")).vectors;
    const vector = { ...vectors[1] };
    delete vector.name;
    const request = createVerificationRequest(vector as VerificationRequest);
    const result = await verifier.verify(request, "standard");

    expect(result.trust_outcome).toBe("trusted");
    expect((result.gateway_mediation as any).route_label).toBe("route:coalition-eu");
    expect((result.gateway_mediation as any).target_authority_id).toBe("did:web:coalition-registry.example");
  });
});
