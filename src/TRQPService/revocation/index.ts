export type RevocationStatusResponse = {
  issued_at: string | null;
  policy_epoch: string | null;
  channel: string;
  age_seconds: number | null;
  feed_descriptor: Record<string, unknown>;
};


export type RevocationProcessState = {

    checkStatus:(entityId: string) => Promise<boolean>
    revocationStatus:() => Promise<RevocationStatusResponse>
    
}



