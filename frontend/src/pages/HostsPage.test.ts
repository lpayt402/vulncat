import { describe, expect, it } from 'vitest';
import { hostQueryFromSearchParams } from './HostsPage';

describe('hostQueryFromSearchParams', () => {
  it('produces the canonical versioned host-query contract', () => {
    const params = new URLSearchParams();
    params.set('q', 'prod-web');
    params.set('ip', '10.20.30.40');
    params.set('ip_scope', 'history');
    params.append('team', 'Platform');
    params.append('environment', 'production');
    params.append('tag', 'pci');
    params.append('tag', 'internet-facing');
    params.set('tag_match', 'all');
    params.append('severity', 'medium');
    params.append('maturity', 'mature');
    params.append('sla', 'overdue');
    params.set('identity_review_state', 'exclude_unresolved');

    expect(hostQueryFromSearchParams(params)).toMatchObject({
      schema_version: 1,
      q: 'prod-web',
      ip_addresses: ['10.20.30.40'],
      ip_scope: 'history',
      administrative_teams: ['Platform'],
      environments: ['production'],
      tags: { values: ['pci', 'internet-facing'], match: 'all' },
      open_severities: ['medium'],
      maturity_states: ['mature'],
      sla_states: ['overdue'],
      identity_review_state: 'exclude_unresolved',
      sort: [{ field: 'canonical_hostname', direction: 'asc' }],
    });
  });

  it('keeps filters empty instead of inventing evidence', () => {
    const query = hostQueryFromSearchParams(new URLSearchParams());
    expect(query.q).toBeUndefined();
    expect(query.ip_addresses).toEqual([]);
    expect(query.system_owners).toEqual([]);
    expect(query.tags).toBeUndefined();
  });
});
