import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MantineProvider } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { apiRequest, downloadFromApi } from '../api/client';
import { ServicesPage } from './ServicesPage';

const session = vi.hoisted(() => ({ role: 'read_only' }));
vi.mock('../auth/AuthContext', () => ({ useAuth: () => ({ user: { role: session.role } }) }));
vi.mock('../api/client', async (importOriginal) => ({ ...await importOriginal<typeof import('../api/client')>(), apiRequest: vi.fn(), downloadFromApi: vi.fn() }));

const vip = { id: 'vip-1', kind: 'vip', native_id: 'checkout-vip', label: 'Checkout VIP', network_scope: 'production-east', ip_address: '10.0.0.9', source: 'network inventory', instance: 'east', facts: {}, version: 1 };
const host = { ...vip, id: 'host-1', kind: 'host', native_id: 'backend-1', label: 'Backend one', asset_id: 'asset-1' };
const rows = [
  { observation_id: 'finding-1', observation_kind: 'vulnerability', vulnerability_id: 'VULN-42', native_status: 'Open', source: 'scanner', instance: 'east', observed_at: '2026-09-01T00:00:00Z', imported_at: '2026-10-01T00:00:00Z', age_days: 31, time_meaning: 'source_observed', node_id: 'vip-1', node_kind: 'vip', node_label: 'Checkout VIP', network_scope: 'production-east', attribution_status: 'review_needed', attribution_reason: 'A shared address does not identify a backend.', attribution_id: 'finding-1', attribution_version: 2, evidence: { operating_system: 'Conflicting Linux and Windows claims' } },
  { observation_id: 'coverage-1', observation_kind: 'coverage', coverage_outcome: 'unreachable', source: 'scanner', instance: 'east', observed_at: null, imported_at: '2026-10-01T00:00:00Z', age_days: null, time_meaning: 'unknown', node_id: 'vip-1', node_kind: 'vip', node_label: 'Checkout VIP', attribution_status: 'attributed', attribution_reason: 'Explicit listener', evidence: {} },
];

function setupMock() {
  vi.mocked(apiRequest).mockImplementation(async (path) => {
    if (path.includes('/nodes')) return { revision: 4, total: 21, offset: 0, limit: 20, items: path.includes('offset=20') ? [host] : [vip] } as never;
    if (path.includes('/report')) return { revision: 4, total: 2, offset: 0, limit: 25, counts: { inventory: 0, vulnerability: 1, coverage: 1 }, items: path.includes('node_id=host-1') ? [] : rows } as never;
    if (path.includes('/graph')) return { revision: 4, total: 21, offset: 0, limit: 20, nodes: [vip, host], relationship_total: 21, relationship_offset: 0, relationship_limit: 20, relationships: [{ id: 'rel-1', kind: 'backed_by', from_node_id: 'vip-1', to_node_id: 'host-1', from_node_label: 'Checkout VIP', to_node_label: 'Backend one', evidence: { reason: 'Network inventory' }, source: 'network inventory', instance: 'east' }] } as never;
    if (path.includes('/history')) return { revision: 4, total: 0, offset: 0, limit: 20, items: [] } as never;
    return { total: 0, items: [] } as never;
  });
}

function renderPage() {
  return render(<MantineProvider><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><ServicesPage /></MemoryRouter></QueryClientProvider></MantineProvider>);
}
beforeEach(() => { session.role = 'read_only'; setupMock(); });
afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe('service exposure', () => {
  it('requires an explicit node choice and shows scoped uncertainty, source time, and coverage separately', async () => {
    renderPage();
    const user = userEvent.setup();
    expect(await screen.findByRole('button', { name: /Select Checkout VIP/ })).toBeInTheDocument();
    expect(screen.getByText('Choose a node to inspect its exposure.')).toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/report'))).toBe(false);
    await user.click(screen.getByRole('button', { name: /Select Checkout VIP/ }));
    expect(await screen.findByText('VULN-42')).toBeInTheDocument();
    expect(screen.getByText('Unreachable')).toBeInTheDocument();
    expect(screen.getByText('A shared address does not identify a backend.')).toBeInTheDocument();
    expect(screen.getByText(/31 days old/)).toBeInTheDocument();
    expect(screen.getByText('Observation time unknown')).toBeInTheDocument();
    expect(screen.getAllByText(/production-east/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/clean/i)).not.toBeInTheDocument();
  });

  it('pages node choices and relationships with bounded requests and never copies VIP findings to a backend', async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Select Checkout VIP/ }));
    await user.click(screen.getByRole('tab', { name: 'Relationships' }));
    expect(await screen.findByText('Backed by')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Next relationships' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('relationship_offset=20') && path.includes('relationship_limit=20'))).toBe(true));
    await user.click(screen.getByRole('checkbox', { name: 'Browse connections for all nodes' }));
    await user.click(await screen.findByRole('button', { name: 'Next graph nodes' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/graph?offset=20') && !path.includes('node_id='))).toBe(true));
    await user.click(screen.getByRole('button', { name: 'Next nodes' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/nodes?') && path.includes('offset=20') && path.includes('limit=20'))).toBe(true));
    await user.click(await screen.findByRole('button', { name: /Select Backend one/ }));
    await user.click(screen.getByRole('tab', { name: 'Exposure' }));
    expect(await screen.findByText(/Coverage unknown/)).toBeInTheDocument();
    expect(screen.queryByText('VULN-42')).not.toBeInTheDocument();
  });

  it('offers report review to read-only accounts without write controls or requests', async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Select Checkout VIP/ }));
    await screen.findByText('VULN-42');
    await user.click(screen.getByRole('tab', { name: 'Change history' }));
    expect(await screen.findByText('No connection changes recorded.')).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Import connections' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Apply|Undo|Preview connections/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Review attribution/ })).not.toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
  });

  it('previews JSON, requires a reason and explicit confirmation, and applies the exact reviewed payload', async () => {
    session.role = 'administrator';
    const original = vi.mocked(apiRequest).getMockImplementation()!;
    vi.mocked(apiRequest).mockImplementation(async (path, init) => {
      if (path.endsWith('/preview')) return { revision: 4, preview_token: 'review-token', payload_sha256: 'hash', node_ids: {}, changes: [{ entity: 'node', before: null, after: { label: 'New endpoint' } }], counts: { nodes: 1 }, warnings: [] } as never;
      if (path.endsWith('/apply')) return { revision: 5, decision_id: 'decision-1', changes: [], counts: {}, replayed: false } as never;
      return original(path, init);
    });
    renderPage();
    const user = userEvent.setup();
    await screen.findByRole('button', { name: /Select Checkout VIP/ });
    await user.click(screen.getByRole('tab', { name: 'Import connections' }));
    const graph = { source: 'network inventory', instance: 'east', time_meaning: 'unknown', nodes: [], relationships: [], attributions: [] };
    await user.click(screen.getByRole('textbox', { name: 'Connections JSON' }));
    await user.paste(JSON.stringify(graph));
    await user.click(screen.getByRole('button', { name: 'Preview connections' }));
    const apply = await screen.findByRole('button', { name: 'Apply reviewed connections' });
    expect(apply).toBeDisabled();
    expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.endsWith('/apply'))).toBe(false);
    await user.type(screen.getByRole('textbox', { name: 'Reason for this change' }), 'Reviewed network owner evidence');
    await user.click(screen.getByRole('checkbox', { name: /I reviewed these connection changes/ }));
    await user.click(apply);
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.endsWith('/apply'))).toBe(true));
    const body = vi.mocked(apiRequest).mock.calls.find(([path]) => path.endsWith('/apply'))?.[1]?.body as Record<string, unknown>;
    expect(body).toMatchObject({ graph, expected_revision: 4, preview_token: 'review-token', confirmed: true, reason: 'Reviewed network owner evidence' });
    expect(body.request_key).toEqual(expect.any(String));
  });

  it('invalidates a preview when JSON changes and keeps evidence details keyboard accessible', async () => {
    session.role = 'administrator';
    const original = vi.mocked(apiRequest).getMockImplementation()!;
    vi.mocked(apiRequest).mockImplementation(async (path, init) => path.endsWith('/preview') ? { revision: 4, preview_token: 'review-token', changes: [], warnings: [], counts: {} } as never : original(path, init));
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Select Checkout VIP/ }));
    const report = await screen.findByRole('table', { name: /Exposure observations/ });
    const details = within(report).getAllByText('Evidence details')[0];
    details.focus();
    expect(details).toHaveFocus();
    await user.keyboard('{Enter}');
    await user.click(screen.getByRole('tab', { name: 'Import connections' }));
    const json = screen.getByRole('textbox', { name: 'Connections JSON' });
    await user.click(json);
    await user.paste('{"source":"inventory","instance":"east","nodes":[],"relationships":[],"attributions":[],"time_meaning":"unknown"}');
    await user.click(screen.getByRole('button', { name: 'Preview connections' }));
    await screen.findByRole('button', { name: 'Apply reviewed connections' });
    await user.type(json, ' ');
    expect(screen.queryByRole('button', { name: 'Apply reviewed connections' })).not.toBeInTheDocument();
  });

  it('reviews attribution with an explicit bounded node choice and preserves its current version', async () => {
    session.role = 'administrator';
    const original = vi.mocked(apiRequest).getMockImplementation()!;
    vi.mocked(apiRequest).mockImplementation(async (path, init) => {
      if (path.endsWith('/preview')) return { revision: 4, preview_token: 'map-token', changes: [], warnings: [], counts: { attributions: 1 } } as never;
      if (path.endsWith('/apply')) return { revision: 5, decision_id: 'mapping-decision' } as never;
      return original(path, init);
    });
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Select Checkout VIP/ }));
    await user.click(await screen.findByRole('button', { name: 'Review attribution for VULN-42' }));
    const dialog = await screen.findByRole('dialog', { name: 'Review observation attribution' });
    const previewButton = within(dialog).getByRole('button', { name: 'Preview attribution' });
    expect(previewButton).toBeDisabled();
    const nextTargets = await within(dialog).findByRole('button', { name: 'Next attribution targets' });
    await waitFor(() => expect(nextTargets).toBeEnabled());
    await user.click(nextTargets);
    const target = await within(dialog).findByRole('combobox', { name: 'Target for this observation' });
    await waitFor(() => expect(within(target).getByRole('option', { name: /Backend one/ })).toBeInTheDocument());
    await user.selectOptions(within(dialog).getByRole('combobox', { name: 'Attribution status' }), 'attributed');
    await user.selectOptions(target, 'host-1');
    await user.type(within(dialog).getByRole('textbox', { name: 'Reason for attribution' }), 'The authenticated scan identifies this backend.');
    await user.click(previewButton);
    const applyButton = await within(dialog).findByRole('button', { name: 'Apply reviewed attribution' });
    expect(applyButton).toBeDisabled();
    expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.endsWith('/apply'))).toBe(false);
    await user.click(within(dialog).getByRole('checkbox', { name: 'I reviewed this attribution and want to save it.' }));
    await user.click(applyButton);
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.endsWith('/apply'))).toBe(true));
    const request = vi.mocked(apiRequest).mock.calls.find(([path]) => path.endsWith('/apply'))?.[1]?.body as Record<string, unknown>;
    expect(request).toMatchObject({ expected_revision: 4, preview_token: 'map-token', confirmed: true, graph: { source: 'analyst', instance: 'manual-review', intent: 'manual_correction', nodes: [], relationships: [], attributions: [{ observation_id: 'finding-1', node_ref: 'host-1', status: 'attributed', expected_version: 2, reason: 'The authenticated scan identifies this backend.' }] } });
  });

  it('ignores a late preview after its draft changes', async () => {
    session.role = 'administrator';
    let resolvePreview: ((value: unknown) => void) | undefined;
    const original = vi.mocked(apiRequest).getMockImplementation()!;
    vi.mocked(apiRequest).mockImplementation((path, init) => path.endsWith('/preview') ? new Promise((resolve) => { resolvePreview = resolve; }) as never : original(path, init));
    renderPage();
    const user = userEvent.setup();
    await screen.findByRole('button', { name: /Select Checkout VIP/ });
    await user.click(screen.getByRole('tab', { name: 'Import connections' }));
    const json = screen.getByRole('textbox', { name: 'Connections JSON' });
    await user.click(json); await user.paste('{"nodes":[]}');
    await user.click(screen.getByRole('button', { name: 'Preview connections' }));
    await user.type(json, ' ');
    await act(async () => { resolvePreview?.({ revision: 4, preview_token: 'late-token', changes: [], warnings: [], counts: {} }); });
    expect(screen.queryByRole('button', { name: 'Apply reviewed connections' })).not.toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.endsWith('/apply'))).toBe(false);
  });

  it('can return uncertain evidence to review without choosing a target', async () => {
    session.role = 'administrator';
    const original = vi.mocked(apiRequest).getMockImplementation()!;
    vi.mocked(apiRequest).mockImplementation(async (path, init) => path.endsWith('/preview') ? { revision: 4, preview_token: 'review-token', changes: [], counts: {}, warnings: [] } as never : original(path, init));
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Select Checkout VIP/ }));
    await user.click(await screen.findByRole('button', { name: 'Review attribution for VULN-42' }));
    const dialog = await screen.findByRole('dialog', { name: 'Review observation attribution' });
    await user.type(within(dialog).getByRole('textbox', { name: 'Reason for attribution' }), 'The target is uncertain; await owner evidence.');
    await user.click(within(dialog).getByRole('button', { name: 'Preview attribution' }));
    await within(dialog).findByRole('button', { name: 'Apply reviewed attribution' });
    const body = vi.mocked(apiRequest).mock.calls.find(([path]) => path.endsWith('/preview'))?.[1]?.body;
    expect(body).toMatchObject({ graph: { intent: 'manual_correction', attributions: [{ observation_id: 'finding-1', node_ref: null, status: 'review_needed', expected_version: 2 }] } });
    expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.endsWith('/apply'))).toBe(false);
  });

  it('looks up existing hosts on bounded pages without changing the imported JSON', async () => {
    session.role = 'administrator';
    const original = vi.mocked(apiRequest).getMockImplementation()!;
    vi.mocked(apiRequest).mockImplementation(async (path, init) => path.includes('/reconciliation/assets') ? { revision: 4, total: 21, items: [{ id: path.includes('offset=20') ? 'asset-two' : 'asset-one', display_name: 'Backend host' }] } as never : original(path, init));
    renderPage();
    const user = userEvent.setup();
    await screen.findByRole('button', { name: /Select Checkout VIP/ });
    await user.click(screen.getByRole('tab', { name: 'Import connections' }));
    await user.click(screen.getByRole('button', { name: 'Search existing hosts' }));
    await user.selectOptions(await screen.findByRole('combobox', { name: 'Existing host' }), 'asset-one');
    expect(screen.getByRole('textbox', { name: 'Selected host asset ID' })).toHaveValue('asset-one');
    await user.click(screen.getByRole('button', { name: 'Next hosts' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/reconciliation/assets') && path.includes('offset=20') && path.includes('limit=20'))).toBe(true));
    expect(screen.getByRole('textbox', { name: 'Connections JSON' })).toHaveValue('');
    expect(vi.mocked(apiRequest).mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
  });

  it('shows immutable history and guards Undo with its revision, reason, and confirmation', async () => {
    session.role = 'administrator';
    const original = vi.mocked(apiRequest).getMockImplementation()!;
    vi.mocked(apiRequest).mockImplementation(async (path, init) => {
      if (path.includes('/history')) return { revision: 4, total: 1, items: [{ id: 'change-1', decision_id: 'change-1', action: 'apply', reason: 'Owner confirmed routes', occurred_at: '2026-10-01T00:00:00Z', changes: [], undoable: true }] } as never;
      if (path.endsWith('/undo')) return { revision: 5 } as never;
      return original(path, init);
    });
    renderPage();
    const user = userEvent.setup();
    await screen.findByRole('button', { name: /Select Checkout VIP/ });
    await user.click(screen.getByRole('tab', { name: 'Change history' }));
    await user.click(await screen.findByRole('button', { name: 'Undo change change-1' }));
    const confirm = await screen.findByRole('button', { name: 'Confirm undo' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByRole('textbox', { name: 'Reason for undo' }), 'The owner corrected this route');
    expect(confirm).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: 'I reviewed this change and want to undo it.' }));
    await user.click(confirm);
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.endsWith('/undo'))).toBe(true));
    const body = vi.mocked(apiRequest).mock.calls.find(([path]) => path.endsWith('/undo'))?.[1]?.body;
    expect(body).toMatchObject({ decision_id: 'change-1', expected_revision: 4, confirmed: true, reason: 'The owner corrected this route', request_key: expect.any(String) });
  });

  it('downloads the current scoped report page using the shared export endpoint', async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Select Checkout VIP/ }));
    await screen.findByText('VULN-42');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Download format' }), 'markdown');
    await user.click(screen.getByRole('button', { name: 'Download current page' }));
    expect(downloadFromApi).toHaveBeenCalledWith('/api/v1/exposure/report/export?format=markdown&node_id=vip-1&offset=0&limit=25');
  });

  it('keeps conflicting and stale fact observations visible with paged provenance', async () => {
    const original = vi.mocked(apiRequest).getMockImplementation()!;
    vi.mocked(apiRequest).mockImplementation(async (path, init) => {
      if (path.includes('/nodes/vip-1')) return { revision: 4, node: vip, fact_total: 21, facts: [{ id: 'fact-1', observed_at: '2026-01-01T00:00:00Z', imported_at: '2026-10-01T00:00:00Z', payload: { operating_system: 'Windows claim' }, provenance: { source: 'owner inventory', instance: 'legacy-east', time_meaning: 'source_observed' } }] } as never;
      if (path.includes('/nodes')) return { revision: 4, total: 1, items: [{ ...vip, fact_summary: { has_disagreement: true, stale_fact_count: 1 } }] } as never;
      return original(path, init);
    });
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Select Checkout VIP/ }));
    expect(screen.getByText(/sources disagree about this target/)).toBeInTheDocument();
    expect(screen.getByText(/1 older fact observations retained/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Review fact history' }));
    const dialog = await screen.findByRole('dialog', { name: 'Fact history: Checkout VIP' });
    expect(await within(dialog).findByText('owner inventory · legacy-east')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Next fact observations' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/nodes/vip-1?fact_offset=20&fact_limit=20'))).toBe(true));
  });
});
