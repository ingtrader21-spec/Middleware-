// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from '@testing-library/react';
import {afterEach, expect, it, vi} from 'vitest';
import {LeadJourney} from './LeadJourney';

afterEach(cleanup);
const page = {schema_version:'1.0',lead_id:'100-L-00000001', lifecycle_state:'ELIGIBLE', lifecycle_version:3,transitions:[],channel_health:[],suppressions:[],exposures:[],next_cursor:null};
it('shows lifecycle and history when next action is unavailable', async () => {
  const service = {journey:vi.fn().mockResolvedValue(page),nextAction:vi.fn().mockRejectedValue(new Error('Candidate authority unavailable'))};
  render(<LeadJourney leadId={page.lead_id} service={service}/>);
  expect(screen.getByText('Loading lead journey…')).toBeTruthy();
  expect(await screen.findByText('ELIGIBLE')).toBeTruthy();
  expect(await screen.findByText(/Candidate authority unavailable/)).toBeTruthy();
  expect(screen.getByText('No lifecycle or exposure history.')).toBeTruthy();
});
it('keeps loaded history when loading an older page fails and supports retry', async () => {
  const service = {journey:vi.fn().mockResolvedValueOnce({...page,next_cursor:'cursor-1'}).mockRejectedValueOnce(new Error('Read failed')).mockResolvedValue(page),nextAction:vi.fn().mockResolvedValue({eligible:false,reason_codes:['NO_CANDIDATE'],selected:null,next_eligible_at:null})};
  render(<LeadJourney leadId={page.lead_id} service={service}/>);
  fireEvent.click(await screen.findByRole('button',{name:'Load older history'}));
  expect(await screen.findByText('Read failed')).toBeTruthy();
  expect(screen.getByText('ELIGIBLE')).toBeTruthy();
  fireEvent.click(screen.getByRole('button',{name:'Load older history'}));
  await vi.waitFor(()=>expect(service.journey).toHaveBeenCalledTimes(3));
});
it('does not invent lifecycle when no authenticated service is provided', () => {
  render(<LeadJourney leadId={page.lead_id}/>);
  expect(screen.getByText(/Authenticated Leads connection required/)).toBeTruthy();
});

it('retries an initial error and renders next-action reasons and evidence', async () => {
  const service = {journey:vi.fn().mockRejectedValueOnce(new Error('Initial read failed')).mockResolvedValue({...page,
    channel_health:[{channel:'email',address_ref:'addr',state:'valid',reason_code:'DELIVERY_CONFIRMED'}],
    suppressions:[{suppression_id:'s1',scope:'global',channel:null,reason:'USER_REQUEST'}],
  }),nextAction:vi.fn().mockResolvedValue({eligible:false,reason_codes:['SUPPRESSED_GLOBAL'],selected:null,next_eligible_at:null})};
  render(<LeadJourney leadId={page.lead_id} service={service}/>);
  fireEvent.click(await screen.findByRole('button',{name:'Retry journey'}));
  expect(await screen.findByText('ELIGIBLE')).toBeTruthy();
  expect(screen.getByText('SUPPRESSED_GLOBAL')).toBeTruthy();
  expect(screen.getByText('email: valid · DELIVERY_CONFIRMED')).toBeTruthy();
  expect(screen.getByText('global: USER_REQUEST')).toBeTruthy();
});

it('aborts and ignores late responses when the authority changes', async () => {
  let finish!: (value: typeof page) => void;
  const oldService = {journey:vi.fn().mockImplementation(() => new Promise<typeof page>(resolve => {finish = resolve;})),nextAction:vi.fn().mockResolvedValue({reason_codes:['OLD_AUTHORITY'],selected:null})};
  const service = {journey:vi.fn().mockResolvedValue({...page,lifecycle_state:'SUPPRESSED'}),nextAction:vi.fn().mockResolvedValue({reason_codes:['SUPPRESSED_GLOBAL'],selected:null})};
  const {rerender} = render(<LeadJourney leadId={page.lead_id} service={oldService}/>);
  const signal = oldService.journey.mock.calls[0][2] as AbortSignal;
  rerender(<LeadJourney leadId={page.lead_id} service={service}/>);
  expect(signal.aborted).toBe(true);
  expect(await screen.findByText('SUPPRESSED')).toBeTruthy();
  finish({...page,lifecycle_state:'STALE_LEAD'});
  await vi.waitFor(() => expect(screen.queryByText('STALE_LEAD')).toBeNull());
  expect(screen.queryByText('OLD_AUTHORITY')).toBeNull();
});
