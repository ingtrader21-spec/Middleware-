import {useEffect, useRef, useState} from 'react';
import type {Journey, JourneyService, NextAction} from './journey';

export function LeadJourney({leadId, service}: {leadId: string; service?: JourneyService}) {
  // Remount state on identity/authority changes; cancelled requests cannot leak
  // one lead or tenant's history into another view.
  return <JourneyConnection key={leadId} leadId={leadId} service={service}/>;
}
function JourneyConnection({leadId, service}: {leadId: string; service?: JourneyService}) {
  const [page, setPage] = useState<Journey>();
  const [source, setSource] = useState(service);
  const [decision, setDecision] = useState<NextAction>();
  const [error, setError] = useState('');
  const [decisionError, setDecisionError] = useState('');
  const [busy, setBusy] = useState(true);
  const [revision, setRevision] = useState(0);
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  useEffect(() => {
    const request = new AbortController();
    controller.current = request;
    const current = ++generation.current;
    setSource(service); setPage(undefined); setDecision(undefined); setError(''); setDecisionError(''); setBusy(true);
    if (service) {
      void service.journey(leadId, undefined, request.signal).then(value => {
        if (current === generation.current) setPage(value);
      }).catch(value => {
        if (current === generation.current) setError(String(value.message ?? value));
      }).finally(() => {if (current === generation.current) setBusy(false);});
      void service.nextAction(leadId, request.signal).then(value => {
        if (current === generation.current) setDecision(value);
      }).catch(value => {
        if (current === generation.current) setDecisionError(String(value.message ?? value));
      });
    }
    return () => {generation.current++; request.abort();};
  }, [leadId, service, revision]);
  async function older() {
    if (!service || !page?.next_cursor || busy) return;
    const current = generation.current;
    setBusy(true); setError('');
    try {
      const next = await service.journey(leadId, page.next_cursor, controller.current?.signal);
      if (current === generation.current) setPage({...next,
        transitions:[...next.transitions, ...page.transitions], exposures:[...next.exposures, ...page.exposures]});
    } catch (value) {
      if (current === generation.current) setError(value instanceof Error ? value.message : 'Journey read failed');
    } finally {if (current === generation.current) setBusy(false);}
  }
  if (!service) return <section aria-label="Lead journey"><h3>Lead journey</h3><p>Authenticated Leads connection required. Lifecycle and next action are unavailable.</p></section>;
  if (source !== service) return <section aria-label="Lead journey"><p role="status">Loading lead journey…</p></section>;
  return <section aria-label="Lead journey">
    <h3>Lead journey</h3>
    {busy && <p role="status">Loading lead journey…</p>}
    {error && <p role="alert">{error}</p>}
    {!page && !busy && <button onClick={() => setRevision(value => value + 1)}>Retry journey</button>}
    {page && <>
      <dl><dt>Lifecycle</dt><dd>{page.lifecycle_state}</dd><dt>Version</dt><dd>{page.lifecycle_version}</dd></dl>
      <h4>Why / next action</h4>
      {decisionError ? <p role="status">Next action unavailable: {decisionError}</p> : decision ? <>
        <p>{decision.reason_codes.join(', ')}</p>
        <p>{decision.selected ? `${decision.selected.channel} · ${decision.selected.campaign_id}` : 'No action selected'}</p>
        {decision.next_eligible_at && <p>Next eligible: {new Date(decision.next_eligible_at).toLocaleString()}</p>}
        <p>Read-only decision; no outreach is triggered.</p>
      </> : <p role="status">Loading next action…</p>}
      <button disabled={busy} onClick={() => setRevision(value => value + 1)}>Refresh journey and next action</button>
      <h4>Channel health</h4>
      {page.channel_health.length ? <ul>{page.channel_health.map(item => <li key={`${item.channel}:${item.address_ref}`}>{item.channel}: {item.state} · {item.reason_code}</li>)}</ul> : <p>No channel-health evidence.</p>}
      <h4>Suppressions</h4>
      {page.suppressions.length ? <ul>{page.suppressions.map(item => <li key={item.suppression_id}>{item.scope}{item.channel ? ` · ${item.channel}` : ''}: {item.reason}</li>)}</ul> : <p>No recorded suppressions.</p>}
      <h4>Journey history</h4>
      {!page.transitions.length && !page.exposures.length && <p>No lifecycle or exposure history.</p>}
      <ol>{page.transitions.map(item => <li key={item.transition_id}>{new Date(item.occurred_at).toLocaleString()} · {item.to_state} · {item.reason_code}</li>)}</ol>
      <ol>{page.exposures.map(item => <li key={item.exposure_id}>{new Date(item.reserved_at).toLocaleString()} · {item.campaign_id} · {item.channel} · {item.status} · {item.engagement_outcome} · {item.negative_outcome}</li>)}</ol>
      {page.next_cursor && <button disabled={busy} onClick={() => void older()}>Load older history</button>}
    </>}
  </section>;
}
