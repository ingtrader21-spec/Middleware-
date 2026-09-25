import {expect, it, vi} from 'vitest';
import {createJourneyService} from './journey';

it('passes explicit tenant, correlation, encoded identity, cursor and cancellation to the authenticated transport', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response('{}'));
  const controller = new AbortController();
  await createJourneyService('tenant-1', fetcher).journey('lead/a', 'cursor+a', controller.signal);
  expect(fetcher).toHaveBeenCalledWith('/platform/v1/leads/lead%2Fa/journey?limit=100&cursor=cursor%2Ba', {
    method:'GET',signal:controller.signal,headers:{Accept:'application/json','X-Tenant-ID':'tenant-1','X-Correlation-ID':expect.any(String)},
  });
});

it('surfaces canonical next-action errors', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({error:{message:'Authority unavailable'}}), {status:503}));
  await expect(createJourneyService('tenant-1', fetcher).nextAction('lead')).rejects.toThrow('Authority unavailable');
});
