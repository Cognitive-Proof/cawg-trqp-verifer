import { AuthorizationResponse } from "../../models.js"

export type EntityStorageState = {
    findEntity: (value:

        {
            entityId: string,
            authorityId: string,
            action: string,
            resource: string,
            context: Record<string, unknown>,
        }
    ) => Promise<AuthorizationResponse>
    getEvidence: () => Promise<Record<string, unknown>>
}

