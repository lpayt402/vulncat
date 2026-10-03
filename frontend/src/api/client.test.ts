import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiRequest, normalizeCollection, setCsrfToken, toQueryString } from './client';

describe('apiRequest', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    setCsrfToken(null);
  });

  it('serializes typed request bodies and sends the CSRF token for mutations', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ id: 'export-1' }), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      }),
    );
    setCsrfToken('csrf-value');

    await apiRequest('/api/v1/exports', {
      method: 'POST',
      body: {
        asset_scope: { mode: 'host_query', query: { schema_version: 1 } },
        finding_scope: { schema_version: 1, severities: ['medium', 'low'] },
        format: 'xlsx',
      },
    });

    const [, request] = fetchMock.mock.calls[0];
    const headers = new Headers(request?.headers);
    expect(headers.get('x-csrf-token')).toBe('csrf-value');
    expect(headers.get('content-type')).toBe('application/json');
    expect(JSON.parse(String(request?.body))).toMatchObject({
      asset_scope: { mode: 'host_query' },
      format: 'xlsx',
    });
  });

  it('does not send the CSRF token for reads', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    setCsrfToken('csrf-value');
    await apiRequest('/api/v1/assets/query');
    const headers = new Headers(fetchMock.mock.calls[0][1]?.headers);
    expect(headers.has('x-csrf-token')).toBe(false);
  });
});

describe('collection and query helpers', () => {
  it('normalizes alternate paginated response shapes', () => {
    expect(normalizeCollection({ results: [{ id: 'a' }], count: 41, page: 2, limit: 20 })).toEqual({
      items: [{ id: 'a' }],
      total: 41,
      page: 2,
      pageSize: 20,
    });
  });

  it('retains repeated values in query strings', () => {
    expect(toQueryString({ severity: ['medium', 'low'], page: 2 })).toBe(
      '?severity=medium&severity=low&page=2',
    );
  });
});
