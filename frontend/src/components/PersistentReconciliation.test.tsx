import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MantineProvider } from '@mantine/core';
import { apiRequest } from '../api/client';
import { PersistentReconciliation } from './PersistentReconciliation';

vi.mock('../api/client', () => ({ apiRequest: vi.fn() }));

const evidence = {
  id: 'observation-1', asset_id: null, version: 3, review_status: 'open',
  rule: 'hostname_match', explanation: 'Hostname is a possible match.', confidence: 0.82,
  candidate_ids: ['asset-1'],
  observation: {
    kind: 'inventory', asset: { fqdn: 'server-1.example.test', native_ids: [] }, observed_at: '2026-10-01T12:00:00Z',
    vulnerability: { vulnerability_id: 'VULN-12', native_status: 'Open', cves: ['CVE-2025-1234', 'CVE-2024-4567'] },
    coverage: { outcome: 'unreachable', complete: false, authenticated: false },
    provenance: { source: 'inventory', instance: 'prod-east', record_number: 4, file_sha256: 'abc123' }, warnings: [],
  },
};

function renderPanel() {
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() });
  return render(<MantineProvider><PersistentReconciliation /></MantineProvider>);
}

async function choose(user: ReturnType<typeof userEvent.setup>, label: string, option: string) {
  const input = screen.getByRole('textbox', { name: label });
  await user.click(input);
  const optionElement = await waitFor(() => {
    const listbox = [...document.querySelectorAll('[role="listbox"]')]
      .find((node) => node.getAttribute('aria-labelledby') === `${input.id}-label`);
    const match = [...(listbox?.querySelectorAll('[data-combobox-option]') ?? [])]
      .find((node) => node.textContent?.trim() === option);
    if (!match) throw new Error(`Option ${option} is not available`);
    return match as HTMLElement;
  });
  await user.click(optionElement);
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('PersistentReconciliation', () => {
  it('shows paged evidence and opens provenance and assignment history', async () => {
    const detail = {
      ...evidence,
      locators: [{ batch_id: 'batch-1', file_sha256: 'abc123', filename: 'inventory.csv', record_number: 4, imported_at: '2026-10-01T12:01:00Z' }],
      locator_total: 1,
      history: [{ version: 3, asset_id: null, review_status: 'open', decision_id: null, occurred_at: '2026-10-01T12:01:00Z' }],
      history_total: 3,
    };
    vi.mocked(apiRequest).mockImplementation(async (path: string) => {
      if (path.includes('/observations/observation-1')) return detail as never;
      if (path.includes('/observations')) return { revision: 12, total: 1, offset: 0, limit: 50, items: [evidence] } as never;
      if (path.includes('/decisions')) return { revision: 12, total: 0, items: [] } as never;
      return { total: 0, items: [] } as never;
    });
    renderPanel();

    expect(await screen.findByText('server-1.example.test')).toBeInTheDocument();
    expect(screen.getByText('Hostname is a possible match.')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Details for server-1.example.test' }));
    expect(await screen.findByText(/File: inventory\.csv/)).toBeInTheDocument();
    expect(screen.getByText(/Version 3/)).toBeInTheDocument();
    expect(screen.getByText(/Record: 4/)).toBeInTheDocument();
    expect(screen.getByText('Vulnerability: VULN-12')).toBeInTheDocument();
    expect(screen.getByText('Native status: Open')).toBeInTheDocument();
    expect(screen.getByText('CVEs: CVE-2025-1234, CVE-2024-4567')).toBeInTheDocument();
    expect(screen.getByText('Coverage outcome: Unreachable')).toBeInTheDocument();
    expect(screen.getByText('Full-scope check: No')).toBeInTheDocument();
    expect(screen.getByText('Authenticated check: No')).toBeInTheDocument();
  });

  it('shows the current assigned asset name or a clear unavailable-name fallback', async () => {
    const named = { ...evidence, id: 'assigned-1', asset_id: 'asset-1', asset_name: 'Web server', review_status: 'assigned' as const };
    const unnamed = { ...evidence, id: 'assigned-2', asset_id: 'asset-2', asset_name: null, review_status: 'assigned' as const };
    vi.mocked(apiRequest).mockImplementation(async (path: string) => {
      if (path.includes('/observations')) return { revision: 12, total: 2, offset: 0, limit: 50, items: [named, unnamed] } as never;
      if (path.includes('/decisions')) return { revision: 12, total: 0, items: [] } as never;
      return { total: 0, items: [] } as never;
    });
    renderPanel();

    expect(await screen.findByText('Current asset: Web server')).toBeInTheDocument();
    expect(screen.getByText('Current asset: Name not available')).toBeInTheDocument();
  });

  it('ignores an observation detail response that finishes after a refresh', async () => {
    const user = userEvent.setup();
    let resolveDetail: ((value: unknown) => void) | undefined;
    const detail = {
      ...evidence,
      locators: [], locator_total: 0, history: [], history_total: 0,
    };
    vi.mocked(apiRequest).mockImplementation((path: string) => {
      if (path.includes('/observations/observation-1')) {
        return new Promise((resolve) => { resolveDetail = resolve; }) as never;
      }
      if (path.includes('/observations')) return Promise.resolve({ revision: 12, total: 1, offset: 0, limit: 50, items: [evidence] }) as never;
      if (path.includes('/decisions')) return Promise.resolve({ revision: 12, total: 0, items: [] }) as never;
      return Promise.resolve({ total: 0, items: [] }) as never;
    });
    renderPanel();
    await screen.findByText('server-1.example.test');
    await user.click(screen.getByRole('button', { name: 'Details for server-1.example.test' }));
    await user.click(screen.getByRole('button', { name: 'Refresh evidence' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/observations?')).length).toBeGreaterThan(1));
    await act(async () => { resolveDetail?.(detail); });

    expect(screen.queryByText('Evidence details: server-1.example.test')).not.toBeInTheDocument();
  });

  it('corrects evidence to an asset without a canonical hostname', async () => {
    const user = userEvent.setup();
    const assignedEvidence = { ...evidence, id: 'assigned-unnamed-target', asset_id: 'asset-old', asset_name: 'Old asset', review_status: 'assigned' as const };
    vi.mocked(apiRequest).mockImplementation(async (path: string) => {
      if (path.includes('/observations')) return { revision: 12, total: 1, offset: 0, limit: 50, items: [assignedEvidence] } as never;
      if (path.includes('/assets')) return { total: 1, items: [{ id: 'asset-unnamed', canonical_hostname: null, display_name: 'Unnamed asset (abc123)' }] } as never;
      if (path.includes('/decisions')) return { revision: 12, total: 0, items: [] } as never;
      return { total: 0, items: [] } as never;
    });
    renderPanel();
    await screen.findByText('server-1.example.test');
    await user.click(screen.getByRole('checkbox', { name: 'Select evidence from server-1.example.test' }));
    await user.type(screen.getByRole('textbox', { name: 'Find assets by name or ID' }), 'abc123');
    await user.click(screen.getByRole('button', { name: 'Search assets' }));
    await choose(user, 'Target asset', 'Unnamed asset (abc123) (ID: asset-unnamed)');
    await user.type(screen.getByRole('textbox', { name: 'Reason' }), 'Confirm this source ID');
    await user.click(screen.getByRole('button', { name: 'Review action' }));

    expect(await screen.findByText(/assigns the selected evidence to Unnamed asset \(abc123\)/i)).toBeInTheDocument();
  });

  it('browses bounded asset pages and distinguishes assets by ID, including unnamed assets', async () => {
    const user = userEvent.setup();
    const firstPage = Array.from({ length: 20 }, (_, index) => ({
      id: `asset-${index}`,
      canonical_hostname: index < 2 ? 'duplicate.example.test' : `host-${index}.example.test`,
      display_name: index < 2 ? 'duplicate.example.test' : `host-${index}.example.test`,
    }));
    const finalAsset = { id: 'asset-unnamed-1234', canonical_hostname: null, display_name: 'Unnamed asset (1234)' };
    vi.mocked(apiRequest).mockImplementation(async (path: string) => {
      if (path.includes('/observations')) return { revision: 12, total: 1, offset: 0, limit: 50, items: [evidence] } as never;
      if (path.includes('/assets')) {
        const offset = new URL(path, 'http://localhost').searchParams.get('offset');
        return (offset === '20' ? { total: 21, items: [finalAsset] } : { total: 21, items: firstPage }) as never;
      }
      if (path.includes('/decisions')) return { revision: 12, total: 0, items: [] } as never;
      return { total: 0, items: [] } as never;
    });
    renderPanel();
    await screen.findByText('server-1.example.test');
    await user.click(screen.getByRole('checkbox', { name: 'Select evidence from server-1.example.test' }));
    await user.click(screen.getByRole('button', { name: 'Browse assets' }));
    expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/assets?q=&offset=0&limit=20'))).toBe(true);
    const targetInput = screen.getByRole('textbox', { name: 'Target asset' });
    await user.click(targetInput);
    const targetListbox = await waitFor(() => {
      const listbox = [...document.querySelectorAll('[role="listbox"]')]
        .find((node) => node.getAttribute('aria-labelledby') === `${targetInput.id}-label`);
      if (!listbox || !listbox.querySelector('[data-combobox-option]')) throw new Error('Target choices are not open');
      return listbox;
    });
    const duplicateOptions = [...targetListbox.querySelectorAll('[data-combobox-option]')];
    const duplicateLabels = duplicateOptions.map((option) => option.textContent?.trim());
    expect(duplicateLabels).toContain('duplicate.example.test (ID: asset-0)');
    expect(duplicateLabels).toContain('duplicate.example.test (ID: asset-1)');
    const firstDuplicate = duplicateOptions.find((option) => option.textContent?.trim() === 'duplicate.example.test (ID: asset-0)');
    expect(firstDuplicate).toBeDefined();
    await user.click(firstDuplicate as HTMLElement);
    await user.click(screen.getByRole('button', { name: 'Next assets' }));
    expect(await screen.findByText('Unnamed asset (1234) (ID: asset-unnamed-1234)')).toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/assets?q=&offset=20&limit=20'))).toBe(true);
    await choose(user, 'Target asset', 'Unnamed asset (1234) (ID: asset-unnamed-1234)');
    await user.type(screen.getByRole('textbox', { name: 'Reason' }), 'Choose this ID-only asset');
    await user.click(screen.getByRole('button', { name: 'Review action' }));
    expect(await screen.findByText(/assigns the selected evidence to Unnamed asset \(1234\)/i)).toBeInTheDocument();
  });

  it('assigns selected evidence with current revision, versions, target and reason', async () => {
    const user = userEvent.setup();
    vi.mocked(apiRequest).mockImplementation(async (path: string) => {
      if (path.includes('/observations/observation-1')) return {
        ...evidence,
        locators: [], locator_total: 0, history: [], history_total: 0,
      } as never;
      if (path.includes('/observations')) return { revision: 12, total: 1, offset: 0, limit: 50, items: [evidence] } as never;
      if (path.includes('/assets')) return { total: 1, items: [{ id: 'asset-1', canonical_hostname: 'server-1.example.test' }] } as never;
      if (path.endsWith('/decisions')) return { id: 'decision-1', revision: 13, action: 'assign', changed_rows: 1, replayed: false } as never;
      if (path.includes('/decisions')) return { revision: 12, total: 0, items: [] } as never;
      return {} as never;
    });
    renderPanel();
    await screen.findByText('server-1.example.test');
    await user.click(screen.getByRole('button', { name: 'Details for server-1.example.test' }));
    expect(await screen.findByText('Evidence details: server-1.example.test')).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'Select evidence from server-1.example.test' }));
    await user.type(screen.getByRole('textbox', { name: 'Find assets by name or ID' }), 'server-1');
    await user.click(screen.getByRole('button', { name: 'Search assets' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/assets?q=server-1'))).toBe(true));
    await choose(user, 'Target asset', 'server-1.example.test (ID: asset-1)');
    await user.type(screen.getByRole('textbox', { name: 'Reason' }), 'Verified against the current inventory');
    await user.click(screen.getByRole('button', { name: 'Review action' }));
    expect(await screen.findByText(/assigns the selected evidence to server-1\.example\.test/i)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save decision' }));
    await waitFor(() => expect(screen.queryByText('Evidence details: server-1.example.test')).not.toBeInTheDocument());

    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path, init]) => (
      path.endsWith('/decisions') && init?.method === 'POST'
    ))).toBe(true));
    const request = vi.mocked(apiRequest).mock.calls.find(([path, init]) => path.endsWith('/decisions') && init?.method === 'POST');
    expect(request?.[1]?.body).toMatchObject({
      expected_revision: 12,
      action: 'assign',
      observation_ids: ['observation-1'],
      expected_versions: { 'observation-1': 3 },
      target_asset_id: 'asset-1',
      reason: 'Verified against the current inventory',
    });
  });

  it('reports stale decisions and does not retry them automatically', async () => {
    const user = userEvent.setup();
    vi.mocked(apiRequest).mockImplementation(async (path: string, init) => {
      if (path.includes('/observations')) return { revision: 12, total: 1, offset: 0, limit: 50, items: [evidence] } as never;
      if (path.endsWith('/decisions') && init?.method === 'POST') throw new Error('409: Revision changed; refresh and review the latest evidence');
      if (path.includes('/decisions')) return { revision: 12, total: 0, items: [] } as never;
      return { total: 0, items: [] } as never;
    });
    renderPanel();
    await screen.findByText('server-1.example.test');
    await user.click(screen.getByRole('checkbox', { name: 'Select evidence from server-1.example.test' }));
    await choose(user, 'Action', 'Reject this evidence');
    await user.type(screen.getByRole('textbox', { name: 'Reason' }), 'Check the stale choice');
    await user.click(screen.getByRole('button', { name: 'Review action' }));
    await user.click(await screen.findByRole('button', { name: 'Save decision' }));

    expect(await screen.findByText(/changed while you were reviewing/i)).toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.filter(([path, init]) => path.endsWith('/decisions') && init?.method === 'POST')).toHaveLength(1);
    expect(screen.getAllByRole('button', { name: 'Refresh evidence' })).toHaveLength(2);
  });

  it('splits only selected evidence and sends the source asset explicitly', async () => {
    const user = userEvent.setup();
    const assignedEvidence = { ...evidence, asset_id: 'asset-source', review_status: 'assigned' as const };
    vi.mocked(apiRequest).mockImplementation(async (path: string, init) => {
      if (path.includes('/observations')) return { revision: 22, total: 1, offset: 0, limit: 50, items: [assignedEvidence] } as never;
      if (path.endsWith('/decisions') && init?.method === 'POST') return { id: 'decision-split', revision: 23, action: 'split', changed_rows: 1, replayed: false } as never;
      if (path.includes('/decisions')) return { revision: 22, total: 0, items: [] } as never;
      if (path.includes('/assets')) return { total: 1, items: [{ id: 'asset-source', canonical_hostname: null, display_name: 'Unnamed asset (source)' }] } as never;
      return {} as never;
    });
    renderPanel();
    await screen.findByText('server-1.example.test');
    await user.click(screen.getByRole('checkbox', { name: 'Select evidence from server-1.example.test' }));
    await choose(user, 'Action', 'Create a separate asset');
    await user.type(screen.getByRole('textbox', { name: 'Reason' }), 'Check whether this can be created separately');
    expect(screen.getByText(/Create and defer apply only to unassigned evidence/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Review action' })).toBeDisabled();
    await choose(user, 'Action', 'Split selected evidence');
    await user.type(screen.getByRole('textbox', { name: 'Find assets by name or ID' }), 'source');
    await user.click(screen.getByRole('button', { name: 'Search assets' }));
    await choose(user, 'Source asset', 'Unnamed asset (source) (ID: asset-source)');
    fireEvent.change(screen.getByRole('textbox', { name: 'Reason' }), { target: { value: 'Separate this device from the shared record' } });
    await user.click(screen.getByRole('button', { name: 'Review action' }));
    expect(await screen.findByText(/moves only the selected evidence from Unnamed asset \(source\)/i)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save decision' }));

    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path, init]) => path.endsWith('/decisions') && init?.method === 'POST')).toBe(true));
    const request = vi.mocked(apiRequest).mock.calls.find(([path, init]) => path.endsWith('/decisions') && init?.method === 'POST');
    expect(request?.[1]?.body).toMatchObject({
      expected_revision: 22,
      action: 'split',
      source_asset_id: 'asset-source',
      observation_ids: ['observation-1'],
      expected_versions: { 'observation-1': 3 },
    });
  });

  it('warns that merge moves all evidence and saves source and target assets', async () => {
    const user = userEvent.setup();
    vi.mocked(apiRequest).mockImplementation(async (path: string, init) => {
      if (path.includes('/observations')) return { revision: 24, total: 0, offset: 0, limit: 50, items: [] } as never;
      if (path.endsWith('/decisions') && init?.method === 'POST') return { id: 'decision-merge', revision: 25, action: 'merge', changed_rows: 2, replayed: false } as never;
      if (path.includes('/decisions')) return { revision: 24, total: 0, items: [] } as never;
      if (path.includes('/assets')) return { total: 2, items: [
        { id: 'asset-source', canonical_hostname: null, display_name: 'Unnamed asset (source)' },
        { id: 'asset-target', canonical_hostname: 'target.example.test' },
      ] } as never;
      return {} as never;
    });
    renderPanel();
    await screen.findByText('Persistent evidence review');
    await choose(user, 'Action', 'Merge assets');
    await user.type(screen.getByRole('textbox', { name: 'Find assets by name or ID' }), 'example.test');
    await user.click(screen.getByRole('button', { name: 'Search assets' }));
    await choose(user, 'Source asset', 'Unnamed asset (source) (ID: asset-source)');
    await choose(user, 'Target asset', 'target.example.test (ID: asset-target)');
    expect(screen.getByRole('textbox', { name: 'Action' })).toHaveValue('Merge assets');
    expect(screen.getByRole('alert', { name: 'Merge consequence' })).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Source asset' })).toHaveValue('Unnamed asset (source) (ID: asset-source)');
    expect(screen.getByRole('textbox', { name: 'Target asset' })).toHaveValue('target.example.test (ID: asset-target)');
    await user.type(screen.getByRole('textbox', { name: 'Reason' }), 'These hosts are the same managed device');
    expect(screen.getByRole('button', { name: 'Review action' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Review action' }));
    expect(await screen.findByText(/all persistent evidence from Unnamed asset \(source\) to target\.example\.test/i)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save decision' }));

    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path, init]) => path.endsWith('/decisions') && init?.method === 'POST')).toBe(true));
    const request = vi.mocked(apiRequest).mock.calls.find(([path, init]) => path.endsWith('/decisions') && init?.method === 'POST');
    expect(request?.[1]?.body).toMatchObject({
      expected_revision: 24,
      action: 'merge',
      source_asset_id: 'asset-source',
      target_asset_id: 'asset-target',
      observation_ids: [],
    });
  });

  it('requires a reason and previews the consequence before undoing an audit decision', async () => {
    const user = userEvent.setup();
    const priorDecision = {
      id: 'decision-5', action: 'assign' as const, reason: 'Previous correction', actor_user_id: 'admin-1',
      occurred_at: '2026-10-01T13:00:00Z', undone: false, reversible: true,
    };
    vi.mocked(apiRequest).mockImplementation(async (path: string, init) => {
      if (path.includes('/observations')) return { revision: 31, total: 0, offset: 0, limit: 50, items: [] } as never;
      if (path.endsWith('/decisions') && init?.method === 'POST') return { id: 'decision-6', revision: 32, action: 'undo', changed_rows: 1, replayed: false } as never;
      if (path.includes('/decisions')) return { revision: 31, total: 1, items: [priorDecision] } as never;
      return { total: 0, items: [] } as never;
    });
    renderPanel();
    await screen.findByText('Previous correction');
    await user.click(screen.getByRole('button', { name: 'Undo' }));
    await user.type(screen.getByRole('textbox', { name: 'Reason' }), 'Undo after confirming the source export');
    await user.click(screen.getByRole('button', { name: 'Review action' }));
    expect(await screen.findByText(/reverses .Previous correction./i)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save decision' }));

    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path, init]) => path.endsWith('/decisions') && init?.method === 'POST')).toBe(true));
    const request = vi.mocked(apiRequest).mock.calls.find(([path, init]) => path.endsWith('/decisions') && init?.method === 'POST');
    expect(request?.[1]?.body).toMatchObject({
      expected_revision: 31,
      action: 'undo',
      undo_decision_id: 'decision-5',
      observation_ids: [],
      expected_versions: {},
      reason: 'Undo after confirming the source export',
    });
  });
});
