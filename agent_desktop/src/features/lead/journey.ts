export interface Journey {
  schema_version: string;
  lead_id: string;
  lifecycle_state: string;
  lifecycle_version: number;
  transitions: {transition_id: string; to_state: string; reason_code: string; occurred_at: string; lifecycle_version: number}[];
  channel_health: {channel: string; address_ref: string; state: string; reason_code: string}[];
  suppressions: {suppression_id: string; scope: string; channel: string | null; reason: string}[];
  exposures: {exposure_id: string; campaign_id: string; channel: string; status: string; reserved_at: string; engagement_outcome: string; negative_outcome: string}[];
  next_cursor: string | null;
}
export interface NextAction {
  eligible: boolean;
  reason_codes: string[];
  selected: {campaign_id: string; channel: string} | null;
  next_eligible_at: string | null;
}
export interface JourneyService {
  journey(leadId: string, cursor?: string, signal?: AbortSignal): Promise<Journey>;
  nextAction(leadId: string, signal?: AbortSignal): Promise<NextAction>;
}

// The host supplies an authenticated transport. Never persist credentials or
// infer a tenant/public lead identity from the desktop's synthetic fixture.
export function createJourneyService(tenantId: string, authenticatedFetch: typeof fetch): JourneyService {
  async function read<T>(leadId: string, resource: string, signal?: AbortSignal): Promise<T> {
    const response = await authenticatedFetch(`/platform/v1/leads/${encodeURIComponent(leadId)}/${resource}`, {
      method: 'GET', signal, headers: {'Accept':'application/json', 'X-Tenant-ID':tenantId, 'X-Correlation-ID':crypto.randomUUID()},
    });
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw new Error(body?.error?.message ?? `Lead read unavailable (${response.status})`);
    }
    return response.json() as Promise<T>;
  }
  return {
    journey: (leadId, cursor, signal) => read<Journey>(leadId, `journey?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, signal),
    nextAction: (leadId, signal) => read<NextAction>(leadId, 'next-action', signal),
  };
}
