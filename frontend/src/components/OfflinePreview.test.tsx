import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MantineProvider } from '@mantine/core';
import { apiRequest } from '../api/client';
import { OfflinePreview } from './OfflinePreview';

vi.mock('../api/client', () => ({
  apiRequest: vi.fn(),
}));

function renderOfflinePreview() {
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() });
  return render(<MantineProvider><OfflinePreview /></MantineProvider>);
}

async function chooseSelect(user: ReturnType<typeof userEvent.setup>, label: string, option: string) {
  await user.click(await screen.findByRole('textbox', { name: label }));
  const optionElement = await waitFor(() => {
    const match = [...document.querySelectorAll('[data-combobox-option]')].find((node) => node.textContent?.trim() === option);
    if (!match) throw new Error(`Option ${option} is not available`);
    return match as HTMLElement;
  });
  await user.click(optionElement);
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('OfflinePreview', () => {
  it('explains that the reconciliation preview is transient', () => {
    renderOfflinePreview();

    expect(screen.getByText(/preview only/i)).toBeInTheDocument();
    expect(screen.getByText(/no changes are saved/i)).toBeInTheDocument();
  });

  it('explains the supported infrastructure object types and review behavior', async () => {
    const user = userEvent.setup();
    vi.mocked(apiRequest).mockResolvedValue({ columns: ['id', 'object_type'], fields: ['native_id_kind'], notice: 'Ready' } as never);
    renderOfflinePreview();
    const file = new File(['id,object_type\n1,dcim.device'], 'netbox.csv', { type: 'text/csv' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await screen.findByText('Ready');
    await chooseSelect(user, 'Source', 'Infrastructure inventory');

    expect(screen.getByText(/dcim\.device and virtualization\.virtualmachine/i)).toBeInTheDocument();
    expect(screen.getByText(/missing object type needs review/i)).toBeInTheDocument();
    expect(screen.getByText(/other types are rejected/i)).toBeInTheDocument();
  });

  it('submits selected files and ordinary field mappings for a transient preview', async () => {
    const user = userEvent.setup();
    const response = { columns: ['Hostname'], fields: ['hostname'], notice: 'Detected source columns', records_path: 'resources' };
    const preview = {
      total_rows: 2, valid_rows: 1, error_rows: 1, duplicate_rows: 0, total: 1,
      offset: 0, limit: 50, truncated: false,
      items: [{
        observation: {
          kind: 'inventory',
          asset: { native_ids: [{ source: 'inventory', instance: 'prod-east', kind: 'device', value: 'server-1' }] },
          provenance: { source: 'inventory', instance: 'prod-east', record_number: 1 },
          warnings: ['No hostname was provided'],
        },
        decision: { action: 'review' as const, rule: 'native_id_only', explanation: 'Confirm this identifier', candidate_ids: ['candidate-1'], confidence: 0.5 },
      }],
      errors: [{ record_number: 7, error: 'Invalid row', instance: 'prod-east' }], errors_truncated: false,
      action_counts: { match: 0, review: 1, create: 0 }, candidate_checks: 1, persisted: false as const,
    };
    vi.mocked(apiRequest).mockImplementation(async (path: string) => (
      path.includes('/columns') ? response : preview
    ) as never);

    renderOfflinePreview();
    const file = new File(['{"hostname":"server-1"}'], 'inventory.json', { type: 'application/json' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await waitFor(() => expect(apiRequest).toHaveBeenCalledWith('/api/v1/reconciliation/columns', expect.objectContaining({ method: 'POST' })));
    const columnsRequest = vi.mocked(apiRequest).mock.calls.find(([path]) => path.includes('/columns'));
    expect((columnsRequest?.[1]?.body as FormData).get('format')).toBe('json');

    fireEvent.change(await screen.findByPlaceholderText('For example, prod-east'), { target: { value: 'prod-east' } });
    await user.click(await screen.findByRole('button', { name: 'Preview reconciliation' }));

    await waitFor(() => expect(apiRequest).toHaveBeenCalledWith(
      '/api/v1/reconciliation/preview?offset=0&limit=50',
      expect.objectContaining({ method: 'POST', body: expect.any(FormData) }),
    ));
    const request = vi.mocked(apiRequest).mock.calls.find(([path]) => path.includes('/preview'));
    const body = request?.[1]?.body as FormData;
    expect(body.getAll('uploads')).toHaveLength(1);
    expect(JSON.parse(String(body.get('options_json')))).toMatchObject([
      { source: 'inventory', instance: 'prod-east', format: 'json', records_path: 'resources', mapping: { hostname: 'Hostname' } },
    ]);
    expect(screen.getByText(/server-1/)).toBeInTheDocument();
    expect(screen.getByText('Detected source columns')).toBeInTheDocument();
    expect(screen.getByText('No hostname was provided')).toBeInTheDocument();
    expect(screen.getByText(/Record 7.*Invalid row/)).toBeInTheDocument();
    const reviewLabel = screen.getByText('Review', { selector: 'p' });
    expect(within(reviewLabel.closest('.mantine-Card-root')!).getByText('1')).toBeInTheDocument();
  });

  it.each(['scan.nessus', 'scan.xml'])('detects %s as Scanner XML (.nessus)', async (filename) => {
    const user = userEvent.setup();
    renderOfflinePreview();

    const file = new File(['<NessusClientData_v2/>'], filename, { type: 'application/xml' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);

    expect(await screen.findByText('Scanner XML (.nessus) uses its built-in field mapping.')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Scanner observations')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Scanner XML (.nessus)')).toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/columns'))).toBe(false);
  });

  it('reloads column metadata after clearing and reselecting the same file', async () => {
    const user = userEvent.setup();
    vi.mocked(apiRequest).mockResolvedValue({ columns: ['Hostname'], fields: ['hostname'], notice: 'Ready' });
    renderOfflinePreview();
    const file = new File(['{"hostname":"server-1"}'], 'inventory.json', { type: 'application/json' });
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;

    await user.upload(input, file);
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/columns'))).toHaveLength(1));
    await user.click(document.querySelector('.mantine-FileInput-root .mantine-CloseButton-root') as HTMLButtonElement);
    await waitFor(() => expect(screen.queryByText('inventory.json')).not.toBeInTheDocument());
    await user.upload(input, file);

    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/columns'))).toHaveLength(2));
  });

  it('resubmits column discovery with a user supplied records path', async () => {
    const user = userEvent.setup();
    vi.mocked(apiRequest).mockResolvedValue({ columns: ['Hostname'], fields: ['hostname'], notice: 'Ready' });
    renderOfflinePreview();
    const file = new File(['{"resources":{"items":[{"hostname":"server-1"}]}}'], 'inventory.json', { type: 'application/json' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/columns'))).toHaveLength(1));

    const pathInput = await screen.findByPlaceholderText('For JSON envelopes, such as resources or resources.items');
    fireEvent.change(pathInput, { target: { value: 'resources.items' } });
    fireEvent.blur(pathInput);

    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/columns'))).toHaveLength(2));
    const columnsRequest = vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/columns')).at(-1);
    expect((columnsRequest?.[1]?.body as FormData).get('records_path')).toBe('resources.items');
  });

  it.each(['CSV', 'NDJSON', 'Scanner XML (.nessus)'])('clears JSON-only configuration when switching to %s', async (targetFormat) => {
    const user = userEvent.setup();
    const preview = {
      total_rows: 0, valid_rows: 0, error_rows: 0, duplicate_rows: 0, total: 0,
      offset: 0, limit: 50, truncated: false, items: [], errors: [], errors_truncated: false,
      action_counts: { match: 0, review: 0, create: 0 }, candidate_checks: 0, persisted: false as const,
    };
    vi.mocked(apiRequest).mockImplementation(async (path: string, init) => {
      if (path.includes('/columns')) {
        const format = (init?.body as FormData).get('format');
        return (format === 'json'
          ? { columns: ['Hostname'], fields: ['hostname'], notice: 'JSON columns', records_path: 'resources' }
          : { columns: ['Device label'], fields: ['hostname'], notice: 'Text export columns' }) as never;
      }
      return preview as never;
    });
    renderOfflinePreview();
    const file = new File(['{"resources":[{"hostname":"server-1"}]}'], 'inventory.json', { type: 'application/json' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await screen.findByText('JSON columns');
    fireEvent.change(await screen.findByPlaceholderText('For example, prod-east'), { target: { value: 'prod-east' } });
    const pathInput = await screen.findByPlaceholderText('For JSON envelopes, such as resources or resources.items');
    expect(pathInput).toHaveValue('resources');

    if (targetFormat === 'Scanner XML (.nessus)') {
      await chooseSelect(user, 'Source', 'Scanner observations');
    }
    await chooseSelect(user, 'File format', targetFormat);

    expect(screen.queryByPlaceholderText('For JSON envelopes, such as resources or resources.items')).not.toBeInTheDocument();
    if (targetFormat !== 'Scanner XML (.nessus)') await screen.findByText('Text export columns');
    await user.click(await screen.findByRole('button', { name: 'Preview reconciliation' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/preview'))).toBe(true));

    const previewCall = vi.mocked(apiRequest).mock.calls.find(([path]) => path.includes('/preview'));
    const previewBody = previewCall?.[1]?.body as FormData;
    const options = JSON.parse(String(previewBody.get('options_json')));
    expect(options[0].format).toBe(targetFormat === 'Scanner XML (.nessus)' ? 'nessus_xml' : targetFormat.toLowerCase());
    expect(options[0]).not.toHaveProperty('records_path');
    if (targetFormat === 'Scanner XML (.nessus)') {
      expect(options[0].source).toBe('nessus');
      expect(options[0]).not.toHaveProperty('mapping');
    } else {
      expect(options[0].mapping).toEqual({});
    }
    const nonJsonColumnCalls = vi.mocked(apiRequest).mock.calls.filter(([path, init]) => (
      path.includes('/columns') && (init?.body as FormData).get('format') !== 'json'
    ));
    nonJsonColumnCalls.forEach(([, init]) => expect((init?.body as FormData).get('records_path')).toBeNull());
  });

  it('reloads JSON columns and sends the matching JSON path after switching back', async () => {
    const user = userEvent.setup();
    const preview = {
      total_rows: 0, valid_rows: 0, error_rows: 0, duplicate_rows: 0, total: 0,
      offset: 0, limit: 50, truncated: false, items: [], errors: [], errors_truncated: false,
      action_counts: { match: 0, review: 0, create: 0 }, candidate_checks: 0, persisted: false as const,
    };
    const columnRequests: Array<{ format: FormDataEntryValue | null; recordsPath: FormDataEntryValue | null }> = [];
    vi.mocked(apiRequest).mockImplementation(async (path: string, init) => {
      if (path.includes('/columns')) {
        const body = init?.body as FormData;
        const format = body.get('format');
        const recordsPath = body.get('records_path');
        columnRequests.push({ format, recordsPath });
        if (format === 'json') {
          return {
            columns: ['Hostname'], fields: ['hostname'], notice: 'JSON columns',
            ...(recordsPath ? {} : { records_path: 'resources' }),
          } as never;
        }
        return { columns: ['Device label'], fields: ['hostname'], notice: 'Text columns' } as never;
      }
      return preview as never;
    });
    renderOfflinePreview();
    const file = new File(['{"resources":[{"hostname":"server-1"}]}'], 'inventory.json', { type: 'application/json' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await screen.findByText('JSON columns');
    fireEvent.change(await screen.findByPlaceholderText('For example, prod-east'), { target: { value: 'prod-east' } });
    await waitFor(() => expect(screen.getByPlaceholderText('For JSON envelopes, such as resources or resources.items')).toHaveValue('resources'));

    await chooseSelect(user, 'File format', 'CSV');
    await screen.findByText('Text columns');
    expect(screen.queryByPlaceholderText('For JSON envelopes, such as resources or resources.items')).not.toBeInTheDocument();
    await chooseSelect(user, 'File format', 'JSON');
    await screen.findByText('JSON columns');
    await waitFor(() => expect(screen.getByPlaceholderText('For JSON envelopes, such as resources or resources.items')).toHaveValue('resources'));
    await user.click(await screen.findByRole('button', { name: 'Preview reconciliation' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/preview'))).toBe(true));

    const previewCall = vi.mocked(apiRequest).mock.calls.find(([path]) => path.includes('/preview'));
    const options = JSON.parse(String((previewCall?.[1]?.body as FormData).get('options_json')));
    expect(options[0]).toMatchObject({
      format: 'json',
      records_path: 'resources',
      mapping: { hostname: 'Hostname' },
    });
    expect(columnRequests).toEqual([
      { format: 'json', recordsPath: null },
      { format: 'json', recordsPath: 'resources' },
      { format: 'csv', recordsPath: null },
      { format: 'json', recordsPath: null },
      { format: 'json', recordsPath: 'resources' },
    ]);
  });

  it('clears scanner-only metadata when the source changes away from Scanner XML (.nessus)', async () => {
    const user = userEvent.setup();
    const preview = {
      total_rows: 0, valid_rows: 0, error_rows: 0, duplicate_rows: 0, total: 0,
      offset: 0, limit: 50, truncated: false, items: [], errors: [], errors_truncated: false,
      action_counts: { match: 0, review: 0, create: 0 }, candidate_checks: 0, persisted: false as const,
    };
    vi.mocked(apiRequest).mockImplementation(async (path: string) => {
      if (path.includes('/columns')) {
        return { columns: ['Hostname'], fields: ['hostname'], notice: 'CSV columns' } as never;
      }
      return preview as never;
    });
    renderOfflinePreview();
    const file = new File(['<NessusClientData_v2/>'], 'scan.nessus', { type: 'application/xml' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await screen.findByText('Scanner XML (.nessus) uses its built-in field mapping.');

    await chooseSelect(user, 'Source', 'Inventory');

    expect(screen.getByDisplayValue('CSV')).toBeInTheDocument();
    expect(screen.queryByPlaceholderText('For JSON envelopes, such as resources or resources.items')).not.toBeInTheDocument();
    await screen.findByText('CSV columns');
    fireEvent.change(await screen.findByPlaceholderText('For example, prod-east'), { target: { value: 'prod-east' } });
    await user.click(await screen.findByRole('button', { name: 'Preview reconciliation' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/preview'))).toBe(true));

    const previewCall = vi.mocked(apiRequest).mock.calls.find(([path]) => path.includes('/preview'));
    const options = JSON.parse(String((previewCall?.[1]?.body as FormData).get('options_json')));
    expect(options[0]).toMatchObject({ source: 'inventory', format: 'csv', mapping: {} });
    expect(options[0]).not.toHaveProperty('records_path');
    const columnsCall = vi.mocked(apiRequest).mock.calls.find(([path]) => path.includes('/columns'));
    expect((columnsCall?.[1]?.body as FormData).get('format')).toBe('csv');
    expect((columnsCall?.[1]?.body as FormData).get('records_path')).toBeNull();
  });

  it('keeps a user mapping when columns are reread with the same format', async () => {
    const user = userEvent.setup();
    const preview = {
      total_rows: 0, valid_rows: 0, error_rows: 0, duplicate_rows: 0, total: 0,
      offset: 0, limit: 50, truncated: false, items: [], errors: [], errors_truncated: false,
      action_counts: { match: 0, review: 0, create: 0 }, candidate_checks: 0, persisted: false as const,
    };
    vi.mocked(apiRequest).mockImplementation(async (path: string, init) => {
      if (path.includes('/columns')) {
        const body = init?.body as FormData;
        const recordsPath = String(body.get('records_path') ?? '');
        return {
          columns: ['Hostname', 'Asset label'],
          fields: ['hostname'],
          notice: `JSON columns ${recordsPath || 'suggested'}`,
          ...(recordsPath ? {} : { records_path: 'resources' }),
        } as never;
      }
      return preview as never;
    });
    renderOfflinePreview();
    const file = new File(['{"resources":[{"hostname":"server-1"}]}'], 'inventory.json', { type: 'application/json' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await screen.findByText('JSON columns resources');
    await waitFor(() => expect(screen.getByPlaceholderText('For JSON envelopes, such as resources or resources.items')).toHaveValue('resources'));
    await user.click(screen.getByRole('button', { name: 'Column mapping' }));
    await chooseSelect(user, 'Hostname', 'Asset label');

    const pathInput = screen.getByPlaceholderText('For JSON envelopes, such as resources or resources.items');
    fireEvent.change(pathInput, { target: { value: 'resources.items' } });
    fireEvent.blur(pathInput);
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/columns'))).toHaveLength(3));
    await screen.findByText('JSON columns resources.items');
    fireEvent.change(screen.getByPlaceholderText('For example, prod-east'), { target: { value: 'prod-east' } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Preview reconciliation' })).toBeEnabled());
    await user.click(await screen.findByRole('button', { name: 'Preview reconciliation' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(([path]) => path.includes('/preview'))).toBe(true));

    const previewCall = vi.mocked(apiRequest).mock.calls.find(([path]) => path.includes('/preview'));
    const options = JSON.parse(String((previewCall?.[1]?.body as FormData).get('options_json')));
    expect(options[0]).toMatchObject({
      format: 'json',
      records_path: 'resources.items',
      mapping: { hostname: 'Asset label' },
    });
  });

  it.each([false, true])('reloads a previously visited records path after an initial error: %s', async (initialError) => {
    const user = userEvent.setup();
    let alphaRequests = 0;
    vi.mocked(apiRequest).mockImplementation(async (_path, options) => {
      const path = (options?.body as FormData).get('records_path');
      if (path === 'alpha') {
        alphaRequests += 1;
        if (initialError && alphaRequests === 1) throw new Error('Earlier path was invalid');
      }
      return { columns: ['Hostname'], fields: ['hostname'], notice: 'Ready' } as never;
    });
    renderOfflinePreview();
    const file = new File(['{"alpha":[],"beta":[]}'], 'inventory.json', { type: 'application/json' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await screen.findByText('Ready');
    fireEvent.change(screen.getByPlaceholderText('For example, prod-east'), { target: { value: 'fixture' } });
    const pathInput = screen.getByPlaceholderText('For JSON envelopes, such as resources or resources.items');

    fireEvent.change(pathInput, { target: { value: 'alpha' } });
    fireEvent.blur(pathInput);
    await waitFor(() => expect(alphaRequests).toBe(1));
    if (initialError) await screen.findByText('Earlier path was invalid');
    else await screen.findByText('Ready');
    fireEvent.change(pathInput, { target: { value: 'beta' } });
    fireEvent.blur(pathInput);
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/columns'))).toHaveLength(3));
    await screen.findByText('Ready');
    fireEvent.change(pathInput, { target: { value: 'alpha' } });
    fireEvent.blur(pathInput);

    await waitFor(() => expect(alphaRequests).toBe(2));
    expect(await screen.findByText('Ready')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Preview reconciliation' })).toBeEnabled();
  });

  it('saves successful preview evidence with the same request key and payload after a transport failure', async () => {
    const user = userEvent.setup();
    let importAttempts = 0;
    const preview = {
      revision: 3, preview_token: 'signed-synthetic-context',
      total_rows: 2, valid_rows: 1, error_rows: 1, duplicate_rows: 0, total: 1,
      offset: 0, limit: 50, truncated: false,
      items: [{
        observation: { kind: 'inventory', asset: { fqdn: 'server-1.example.test' }, warnings: [] },
        decision: { action: 'create' as const, explanation: 'No existing asset matched.', candidate_ids: [] },
      }],
      errors: [{ record_number: 7, error: 'Missing optional details', instance: 'prod-east' }], errors_truncated: false,
      action_counts: { match: 0, review: 0, create: 1 }, candidate_checks: 0, persisted: false as const,
    };
    const saved = {
      id: 'batch-1', revision: 1, total_rows: 2, valid_rows: 1, error_rows: 1, duplicate_rows: 0,
      new_observations: 1, assigned_rows: 0, review_rows: 0,
      errors: [{ record_number: 7, error: 'Incomplete source row', instance: 'prod-east' }], replayed: false, persisted: true as const,
    };
    vi.mocked(apiRequest).mockImplementation(async (path: string) => {
      if (path.includes('/columns')) return { columns: ['fqdn', 'Asset DNS'], fields: ['fqdn'], notice: 'Columns ready' } as never;
      if (path.includes('/preview')) return preview as never;
      if (path.includes('/imports')) {
        importAttempts += 1;
        if (importAttempts === 1) throw new Error('Network unavailable');
        return saved as never;
      }
      if (path.includes('/observations')) return { revision: 1, total: 0, offset: 0, limit: 50, items: [] } as never;
      if (path.includes('/decisions')) return { revision: 1, total: 0, items: [] } as never;
      return { total: 0, items: [] } as never;
    });
    renderOfflinePreview();
    const file = new File(['fqdn\nserver-1.example.test'], 'inventory.csv', { type: 'text/csv' });
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    expect(screen.queryByRole('button', { name: 'Save evidence' })).not.toBeInTheDocument();
    fireEvent.change(await screen.findByPlaceholderText('For example, prod-east'), { target: { value: 'prod-east' } });
    await user.click(await screen.findByRole('button', { name: 'Preview reconciliation' }));
    await screen.findByText('server-1.example.test');
    await user.click(screen.getByRole('button', { name: 'Save evidence' }));
    expect(await screen.findByText('Network unavailable')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry saving evidence' }));
    expect((await screen.findAllByText(/Evidence saved/)).length).toBeGreaterThan(0);
    expect(screen.getByText(/Record 7.*Incomplete source row/)).toBeInTheDocument();

    const importRequests = vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/imports'));
    expect(importRequests).toHaveLength(2);
    const payloads = importRequests.map(([, init]) => {
      const body = init?.body as FormData;
      return {
        file: (body.getAll('uploads')[0] as File).name,
        options: body.get('options_json'),
        requestKey: body.get('request_key'),
        revision: body.get('expected_revision'),
        previewToken: body.get('preview_token'),
      };
    });
    expect(payloads[0].file).toBe('inventory.csv');
    expect(payloads[1]).toEqual(payloads[0]);
    expect(payloads[0].requestKey).toBeTruthy();
    expect(payloads[0].revision).toBe('3');
    expect(payloads[0].previewToken).toBe('signed-synthetic-context');
    expect(JSON.parse(String(payloads[0].options))).toMatchObject([
      { source: 'inventory', instance: 'prod-east', format: 'csv', mapping: { fqdn: 'fqdn' } },
    ]);

    await user.click(screen.getByRole('button', { name: 'Column mapping' }));
    await chooseSelect(user, 'Fqdn', 'Asset DNS');
    expect(screen.queryByRole('button', { name: 'Evidence saved' })).not.toBeInTheDocument();
    expect(screen.queryByText('server-1.example.test')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Preview reconciliation' }));
    await screen.findByText('server-1.example.test');
    await user.click(screen.getByRole('button', { name: 'Save evidence' }));
    await screen.findByRole('button', { name: 'Evidence saved' });

    const refreshedImportRequests = vi.mocked(apiRequest).mock.calls.filter(([path]) => path.includes('/imports'));
    expect(refreshedImportRequests).toHaveLength(3);
    const previousPayload = refreshedImportRequests[1][1]?.body as FormData;
    const revisedPayload = refreshedImportRequests[2][1]?.body as FormData;
    expect(revisedPayload.get('request_key')).not.toBe(previousPayload.get('request_key'));
    expect(JSON.parse(String(revisedPayload.get('options_json')))).toMatchObject([
      { mapping: { fqdn: 'Asset DNS' } },
    ]);
  });

  it('requires a fresh preview after a save conflict and shows retained review decisions', async () => {
    const user = userEvent.setup();
    const preview = {
      revision: 4, preview_token: 'signed-context',
      total_rows: 1, valid_rows: 1, error_rows: 0, duplicate_rows: 1, total: 1,
      offset: 0, limit: 50, truncated: false, errors: [], errors_truncated: false,
      action_counts: { retain: 1 }, candidate_checks: 0, persisted: false,
      items: [{ observation: { kind: 'inventory', asset: { fqdn: 'retained.example.test' } },
        decision: { action: 'retain', explanation: 'Keep saved rejected decision at version 2.' },
        current_assignment: { review_status: 'rejected', version: 2 } }],
    };
    vi.mocked(apiRequest).mockImplementation(async (path: string) => {
      if (path.includes('/columns')) return { columns: ['hostname'], fields: ['hostname'], notice: 'Ready' } as never;
      if (path.includes('/preview')) return preview as never;
      if (path.includes('/imports')) throw Object.assign(new Error('Evidence changed after preview'), { status: 409 });
      return { revision: 4, total: 0, items: [] } as never;
    });
    renderOfflinePreview();
    await user.upload(document.querySelector('input[type="file"]') as HTMLInputElement,
      new File(['hostname\nretained.example.test'], 'inventory.csv', { type: 'text/csv' }));
    fireEvent.change(await screen.findByPlaceholderText('For example, prod-east'), { target: { value: 'synthetic' } });
    await user.click(screen.getByRole('button', { name: 'Preview reconciliation' }));
    await screen.findByText('Keep saved rejected decision at version 2.');
    expect(screen.getByText('Retained')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save evidence' }));
    await screen.findByText(/Evidence changed after preview/);
    expect(screen.getByRole('button', { name: 'Preview again before saving' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Preview reconciliation' }));
    expect(await screen.findByRole('button', { name: 'Save evidence' })).toBeEnabled();
  });
});
