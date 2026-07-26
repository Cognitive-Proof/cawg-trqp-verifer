import { RecognitionResponse } from "../../models.js";

export type RecognitionProcessState = {

    checkRecognition:(value:{
         authorityId: string,
    recognizedAuthorityId: string,
    context: Record<string, unknown>,
    }) => Promise<RecognitionResponse>
}


