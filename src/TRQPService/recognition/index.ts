import { RecognitionResponse } from "../../models.js";

export type RecognitionProcessState = {

    checkRecognition:(value:{
        entityId: string,
        authorityId: string,
        action: string,
        resource: string,
        context: Record<string, unknown>,
    }) => Promise<RecognitionResponse>
}


