import { useEffect, useRef, useState } from 'react';
import {
  Accordion,
  Alert,
  Badge,
  Button,
  Card,
  FileInput,
  Grid,
  Group,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { IconRefresh, IconUpload } from '@tabler/icons-react';
import { apiRequest } from '../api/client';
import { humanize } from '../utils/format';
import { PersistentReconciliation } from './PersistentReconciliation';

const sources = [
  { value: 'crowdstrike', label: 'Endpoint security' },
  { value: 'pdq_connect', label: 'Endpoint management' },
  { value: 'nessus', label: 'Scanner observations' },
  { value: 'netbox', label: 'Infrastructure inventory' },
  { value: 'active_directory', label: 'Directory records' },
  { value: 'inventory', label: 'Inventory' },
];

const formats = [
  { value: 'csv', label: 'CSV' },
  { value: 'json', label: 'JSON' },
  { value: 'ndjson', label: 'NDJSON' },
  { value: 'nessus_xml', label: 'Scanner XML (.nessus)' },
];

const timeMeanings = [
  { value: 'source_observed', label: 'When the source says it was observed' },
  { value: 'record_updated', label: 'When the source record was updated' },
  { value: 'last_logon', label: 'Last logon time' },
  { value: 'export_snapshot', label: 'When this export was created' },
  { value: 'unknown', label: 'Unknown or unreliable' },
];

interface OfflineFile {
  key: string;
  file: File;
  source: string;
  instance: string;
  format: string;
  networkScope: string;
  timeMeaning: string;
  recordsPath: string;
  columns?: string[];
  fields?: string[];
  columnsPath?: string;
  columnNotice?: string;
  columnError?: string;
  mapping: Record<string, string>;
}

interface PreviewItem {
  observation: {
    kind?: string;
    asset?: {
      fqdn?: string;
      short_hostname?: string;
      ip_addresses?: string[];
      native_ids?: Array<{ source?: string; instance?: string; kind?: string; value?: string }>;
    };
    observed_at?: string | null;
    warnings?: string[];
    provenance?: { source?: string; instance?: string; record_number?: number };
    vulnerability?: { vulnerability_id?: string; native_status?: string };
    coverage?: { outcome?: string };
  };
  decision: {
    action: 'match' | 'review' | 'create' | 'retain';
    rule?: string;
    explanation?: string;
    confidence?: number;
    candidate_ids?: string[];
  };
}

interface PreviewResult {
  notice?: string;
  total_rows: number;
  valid_rows: number;
  error_rows: number;
  duplicate_rows: number;
  total: number;
  offset: number;
  limit: number;
  truncated: boolean;
  items: PreviewItem[];
  errors: Array<{ record_number: number; error: string; file_sha256?: string; instance?: string }>;
  errors_truncated: boolean;
  action_counts: { match?: number; review?: number; create?: number; retain?: number };
  candidate_checks: number;
  persisted: false;
  revision: number;
  preview_token: string;
}

interface SavedEvidenceResult {
  id: string;
  revision: number;
  total_rows: number;
  valid_rows: number;
  error_rows: number;
  duplicate_rows: number;
  new_observations: number;
  assigned_rows: number;
  review_rows: number;
  errors: Array<{ record_number: number; error: string; instance?: string }>;
  replayed: boolean;
  persisted: true;
}

interface SaveSnapshot {
  requestKey: string;
  files: File[];
  optionsJson: string;
  revision: number;
  previewToken: string;
}

const keyFor = (file: File, index: number) => `${file.name}:${file.size}:${file.lastModified}:${index}`;
const columnRequestKey = (fileKey: string, format: string, recordsPath: string) => JSON.stringify([fileKey, format, recordsPath]);
const newRequestKey = () => globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;

function fileDefaults(file: File) {
  const extension = file.name.split('.').pop()?.toLowerCase();
  if (extension === 'nessus' || extension === 'xml') return { source: 'nessus', format: 'nessus_xml' };
  if (extension === 'json') return { source: 'inventory', format: 'json' };
  if (extension === 'ndjson') return { source: 'inventory', format: 'ndjson' };
  return { source: 'inventory', format: 'csv' };
}

function autoMapping(fields: string[], columns: string[]) {
  const byNormalizedName = new Map(columns.map((column) => [column.toLowerCase().replace(/[^a-z0-9]/g, ''), column]));
  return Object.fromEntries(fields.flatMap((field) => {
    const match = byNormalizedName.get(field.toLowerCase().replace(/[^a-z0-9]/g, ''));
    return match ? [[field, match]] : [];
  }));
}

function resetFormatData(file: OfflineFile, format: string): OfflineFile {
  return {
    ...file,
    format,
    recordsPath: '',
    mapping: {},
    columns: undefined,
    fields: undefined,
    columnsPath: undefined,
    columnNotice: undefined,
    columnError: undefined,
  };
}

export function OfflinePreview() {
  const [files, setFiles] = useState<OfflineFile[]>([]);
  const [fileLimitReached, setFileLimitReached] = useState(false);
  const [result, setResult] = useState<PreviewResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [saveSnapshot, setSaveSnapshot] = useState<SaveSnapshot | null>(null);
  const [saveResult, setSaveResult] = useState<SavedEvidenceResult | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [savingEvidence, setSavingEvidence] = useState(false);
  const [persistentRefreshToken, setPersistentRefreshToken] = useState(0);
  const requestVersion = useRef(0);
  const columnRequests = useRef(new Set<string>());

  useEffect(() => {
    files.filter((entry) => entry.format !== 'nessus_xml' && !entry.columns && !entry.columnError).forEach((entry) => {
      const recordsPath = entry.format === 'json' ? entry.recordsPath.trim() : '';
      const requestKey = columnRequestKey(entry.key, entry.format, recordsPath);
      if (columnRequests.current.has(requestKey)) return;
      columnRequests.current.add(requestKey);
      const body = new FormData();
      body.append('upload', entry.file);
      body.append('format', entry.format);
      if (entry.format === 'json' && recordsPath) body.append('records_path', recordsPath);
      void apiRequest<{ columns: string[]; fields: string[]; notice: string; records_path?: string | null }>(
        '/api/v1/reconciliation/columns',
        { method: 'POST', body },
      ).then((columns) => {
        updateFile(entry.key, (current) => {
          if (current.format !== entry.format || current.recordsPath.trim() !== recordsPath) {
            columnRequests.current.delete(requestKey);
            return current;
          }
          const suggestedPath = columns.records_path?.trim();
          if (entry.format === 'json' && !recordsPath && !current.recordsPath.trim() && suggestedPath) {
            return {
              ...current,
              recordsPath: suggestedPath,
              columnsPath: recordsPath,
              columnNotice: columns.notice,
            };
          }
          return {
            ...current,
            columns: columns.columns,
            fields: columns.fields,
            columnsPath: recordsPath,
            columnNotice: columns.notice,
            mapping: { ...autoMapping(columns.fields, columns.columns), ...current.mapping },
          };
        });
      }).catch((error: unknown) => {
        updateFile(entry.key, (current) => {
          if (current.format !== entry.format || current.recordsPath.trim() !== recordsPath) {
            columnRequests.current.delete(requestKey);
            return current;
          }
          return { ...current, columnError: error instanceof Error ? error.message : 'Could not read columns.' };
        });
      });
    });
  }, [files]);

  function invalidatePreview() {
    requestVersion.current += 1;
    setResult(null);
    setRequestError(null);
    setLoading(false);
    setSaveSnapshot(null);
    setSaveResult(null);
    setSaveError(null);
  }

  function updateFile(key: string, change: (current: OfflineFile) => OfflineFile) {
    setFiles((current) => current.map((entry) => entry.key === key ? change(entry) : entry));
  }

  function changeFile(key: string, change: (current: OfflineFile) => OfflineFile) {
    invalidatePreview();
    updateFile(key, change);
  }

  function clearColumnRequests(fileKey: string) {
    columnRequests.current = new Set([...columnRequests.current].filter((requestKey) => (
      (JSON.parse(requestKey) as string[])[0] !== fileKey
    )));
  }

  function selectFiles(selected: File[] | null) {
    invalidatePreview();
    setFileLimitReached((selected?.length ?? 0) > 8);
    const limited = (selected ?? []).slice(0, 8);
    setFiles((current) => limited.map((file, index) => {
      const key = keyFor(file, index);
      return current.find((entry) => entry.key === key) ?? {
        key,
        file,
        ...fileDefaults(file),
        instance: '',
        networkScope: '',
        timeMeaning: 'unknown',
        recordsPath: '',
        mapping: {},
      };
    }));
    const activeKeys = new Set(limited.map((file, index) => keyFor(file, index)));
    columnRequests.current = new Set([...columnRequests.current].filter((requestKey) => {
      const requestFileKey = (JSON.parse(requestKey) as string[])[0];
      return activeKeys.has(requestFileKey);
    }));
  }

  async function requestPreview(nextOffset = 0) {
    const version = ++requestVersion.current;
    setLoading(true);
    setRequestError(null);
    setResult(null);
    const body = new FormData();
    const options = files.map((entry) => {
      body.append('uploads', entry.file);
      const option: Record<string, unknown> = {
        source: entry.source,
        instance: entry.instance.trim(),
        format: entry.format,
        time_meaning: entry.timeMeaning,
      };
      if (entry.networkScope.trim()) option.network_scope = entry.networkScope.trim();
      if (entry.format === 'json' && entry.recordsPath.trim()) option.records_path = entry.recordsPath.trim();
      if (entry.format !== 'nessus_xml') option.mapping = entry.mapping;
      return option;
    });
    const optionsJson = JSON.stringify(options);
    body.append('options_json', optionsJson);
    const submissionFiles = files.map((entry) => entry.file);
    try {
      const next = await apiRequest<PreviewResult>(
        `/api/v1/reconciliation/preview?offset=${nextOffset}&limit=50`,
        { method: 'POST', body },
      );
      if (version === requestVersion.current) {
        setResult(next);
        setSaveSnapshot((current) => current
          && current.revision === next.revision
          && current.optionsJson === optionsJson
          && current.files.length === submissionFiles.length
          && current.files.every((file, index) => file === submissionFiles[index])
          ? { ...current, previewToken: next.preview_token }
          : { requestKey: newRequestKey(), files: submissionFiles, optionsJson, revision: next.revision, previewToken: next.preview_token });
        setSaveResult(null);
        setSaveError(null);
      }
    } catch (error) {
      if (version === requestVersion.current) {
        setRequestError(error instanceof Error ? error.message : 'Preview request failed.');
      }
    } finally {
      if (version === requestVersion.current) setLoading(false);
    }
  }

  async function saveEvidence() {
    if (!saveSnapshot || !result || savingEvidence || saveResult) return;
    const body = new FormData();
    saveSnapshot.files.forEach((file) => body.append('uploads', file));
    body.append('options_json', saveSnapshot.optionsJson);
    body.append('request_key', saveSnapshot.requestKey);
    body.append('expected_revision', String(saveSnapshot.revision));
    body.append('preview_token', saveSnapshot.previewToken);
    setSavingEvidence(true);
    setSaveError(null);
    try {
      const saved = await apiRequest<SavedEvidenceResult>(
        '/api/v1/reconciliation/imports',
        { method: 'POST', body },
      );
      if (saved.persisted !== true) throw new Error('The server did not confirm that evidence was saved.');
      setSaveResult(saved);
      setPersistentRefreshToken((current) => current + 1);
    } catch (error) {
      setSaveError(error instanceof Error ? error.message : 'Could not save source evidence. Try again.');
      if (error instanceof Error && 'status' in error && error.status === 409) setSaveSnapshot(null);
    } finally {
      setSavingEvidence(false);
    }
  }

  const canPreview = files.length > 0 && files.every((entry) => entry.instance.trim() && (entry.format === 'nessus_xml' || entry.columns) && !entry.columnError);

  return (
    <Card className="vb-card" withBorder>
      <Stack>
        <div>
          <Title order={2} size="h4">Offline reconciliation preview</Title>
          <Text size="sm" c="dimmed">Compare up to eight source files before any durable import.</Text>
        </div>
        <Alert color="blue" title="Preview only">
          No changes are saved by this preview. Save source evidence separately below. Scanner reports and finding statuses stay unchanged.
        </Alert>
        <Text size="sm" c="dimmed">
          Source exports vary. Map detected columns to the fields they represent. Examples and compatibility notes use synthetic data.
        </Text>
        <Text size="sm" c="dimmed">
          Identical evidence keeps its saved assignment or review decision. Preview again if evidence changes before saving.
        </Text>
        <FileInput
          label="Source files"
          description="Choose up to 8 files. CSV, JSON, NDJSON, and Scanner XML (.nessus) are supported."
          accept=".csv,.json,.ndjson,.nessus,.xml,text/csv,application/json,application/xml"
          multiple
          value={files.map((entry) => entry.file)}
          onChange={selectFiles}
          leftSection={<IconUpload size={16} />}
          clearable
        />
        {fileLimitReached ? <Alert color="orange">Only the first 8 files were selected.</Alert> : null}
        {files.map((entry, index) => (
          <Card key={entry.key} withBorder padding="sm">
            <Stack gap="sm">
              <Group justify="space-between">
                <Text fw={600}>{entry.file.name}</Text>
                <Badge variant="light">File {index + 1}</Badge>
              </Group>
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <Select label="Source" data={sources} value={entry.source} onChange={(value) => {
                  if (!value) return;
                  const nextFormat = value !== 'nessus' && entry.format === 'nessus_xml' ? 'csv' : entry.format;
                  if (nextFormat !== entry.format) clearColumnRequests(entry.key);
                  changeFile(entry.key, (current) => nextFormat === current.format
                    ? { ...current, source: value }
                    : { ...resetFormatData(current, nextFormat), source: value });
                }} />
                <TextInput label="Instance" placeholder="For example, prod-east" required value={entry.instance} onChange={(event) => {
                  const value = event.currentTarget.value;
                  changeFile(entry.key, (current) => ({ ...current, instance: value }));
                }} />
                <Select label="File format" data={formats.filter((format) => format.value !== 'nessus_xml' || entry.source === 'nessus')} value={entry.format} onChange={(value) => {
                  if (!value) return;
                  clearColumnRequests(entry.key);
                  changeFile(entry.key, (current) => resetFormatData(current, value));
                }} />
                <Select label="Timestamp meaning" data={timeMeanings} value={entry.timeMeaning} onChange={(value) => value && changeFile(entry.key, (current) => ({ ...current, timeMeaning: value }))} />
                <TextInput label="Network scope (optional)" placeholder="For example, corporate" value={entry.networkScope} onChange={(event) => {
                  const value = event.currentTarget.value;
                  changeFile(entry.key, (current) => ({ ...current, networkScope: value }));
                }} />
                {entry.format === 'json' ? (
                  <TextInput label="Records path (optional)" placeholder="For JSON envelopes, such as resources or resources.items" value={entry.recordsPath} onChange={(event) => {
                    const value = event.currentTarget.value;
                    changeFile(entry.key, (current) => ({ ...current, recordsPath: value }));
                  }} onBlur={() => {
                    if (entry.recordsPath.trim() !== entry.columnsPath) {
                      columnRequests.current.delete(columnRequestKey(entry.key, entry.format, entry.recordsPath.trim()));
                      changeFile(entry.key, (current) => ({ ...current, columns: undefined, fields: undefined, columnsPath: undefined, columnNotice: undefined, columnError: undefined }));
                    }
                  }} />
                ) : null}
              </SimpleGrid>
              <Alert color="blue" title="Choose fields carefully">
                Choose a column only when it contains that field. Leave optional fields unmapped when absent; a mapped field missing from a record causes a row error. Blank optional cells mean no value. Record kind must be inventory, vulnerability or coverage when mapped; leave it unmapped to infer it from the supplied fields.
              </Alert>
              {entry.source === 'netbox' ? (
                <Alert color="orange" title="Map infrastructure object type">
                  Supported object types are dcim.device and virtualization.virtualmachine. A missing object type needs review; other types are rejected and require an export limited to devices and virtual machines. Their IDs can overlap.
                </Alert>
              ) : null}
              {entry.columnError ? <Alert color="red" title="Could not read columns">{entry.columnError}</Alert> : null}
              {entry.columnNotice ? <Text size="sm" c="dimmed">{entry.columnNotice}</Text> : null}
              {entry.columns && entry.format !== 'nessus_xml' ? (
                <Accordion key={entry.source} variant="separated" defaultValue={entry.source === 'netbox' ? 'mapping' : undefined}>
                  <Accordion.Item value="mapping">
                    <Accordion.Control>Column mapping</Accordion.Control>
                    <Accordion.Panel>
                      <Grid>
                        {(entry.fields?.length ? entry.fields : entry.columns).map((field) => (
                          <Grid.Col span={{ base: 12, sm: 6, md: 4 }} key={field}>
                            <Select
                              label={humanize(field)}
                              searchable
                              clearable
                              data={entry.columns ?? []}
                              value={entry.mapping[field] ?? null}
                              onChange={(value) => changeFile(entry.key, (current) => {
                                const mapping = { ...current.mapping };
                                if (value) mapping[field] = value;
                                else delete mapping[field];
                                return { ...current, mapping };
                              })}
                            />
                          </Grid.Col>
                        ))}
                      </Grid>
                    </Accordion.Panel>
                  </Accordion.Item>
                </Accordion>
              ) : entry.format === 'nessus_xml' ? (
                <Text size="sm" c="dimmed">Scanner XML (.nessus) uses its built-in field mapping.</Text>
              ) : (
                <Text size="sm" c="dimmed">Reading available columns…</Text>
              )}
            </Stack>
          </Card>
        ))}
        {requestError ? <Alert color="red" title="Preview failed">{requestError}</Alert> : null}
        <Group justify="flex-end">
          <Button leftSection={<IconRefresh size={16} />} disabled={!canPreview} loading={loading} onClick={() => void requestPreview(0)}>
            Preview reconciliation
          </Button>
        </Group>
        {result ? (
          <Stack>
            {result.persisted !== false ? <Alert color="red">The server did not confirm this was a transient preview.</Alert> : null}
            <Alert color="blue" title={result.notice ?? 'Preview only'}>
              No changes are saved by this preview. Candidate matches may be provisional.
            </Alert>
            <Group justify="space-between" align="center">
              <Text size="sm" c="dimmed">Saving keeps source evidence and assignments. It never resolves scanner findings.</Text>
              <Button disabled={!saveSnapshot || Boolean(saveResult)} loading={savingEvidence} onClick={() => void saveEvidence()}>
                {saveResult ? 'Evidence saved' : !saveSnapshot ? 'Preview again before saving' : saveError ? 'Retry saving evidence' : 'Save evidence'}
              </Button>
            </Group>
            {saveError ? <Alert color="red" title="Could not save source evidence">{saveError}</Alert> : null}
            {saveResult ? (
              <Alert color="green" title={saveResult.replayed ? 'Evidence already saved' : 'Evidence saved'}>
                Saved {saveResult.new_observations} new observations; {saveResult.assigned_rows} assigned and {saveResult.review_rows} need review. {saveResult.error_rows} rows had errors.
              </Alert>
            ) : null}
            {saveResult?.errors.length ? (
              <Alert color="orange" title="Saved rows needing attention">
                <Stack gap={4}>{saveResult.errors.map((error, index) => <Text size="sm" key={`${error.record_number}-${index}`}>Record {error.record_number}{error.instance ? ` · ${error.instance}` : ''}: {error.error}</Text>)}</Stack>
              </Alert>
            ) : null}
            <SimpleGrid cols={{ base: 2, sm: 4 }}>
              {[
                ['Rows', result.total_rows], ['Valid', result.valid_rows], ['Errors', result.error_rows], ['Duplicates', result.duplicate_rows],
                ['Match', result.action_counts.match], ['Review', result.action_counts.review], ['Create', result.action_counts.create], ['Retained', result.action_counts.retain], ['Candidate checks', result.candidate_checks],
              ].map(([label, value]) => (
                <Card key={String(label)} padding="sm" withBorder>
                  <Text size="xs" c="dimmed">{label}</Text><Text fw={700}>{Number(value ?? 0).toLocaleString()}</Text>
                </Card>
              ))}
            </SimpleGrid>
            {result.items.length ? (
              <Table.ScrollContainer minWidth={720}>
                <Table striped highlightOnHover>
                  <Table.Thead><Table.Tr><Table.Th>Asset or identifier</Table.Th><Table.Th>Source</Table.Th><Table.Th>Kind</Table.Th><Table.Th>Observed</Table.Th><Table.Th>Decision</Table.Th><Table.Th>Explanation</Table.Th><Table.Th>Warnings</Table.Th></Table.Tr></Table.Thead>
                  <Table.Tbody>
                    {result.items.map((item, index) => (
                      <Table.Tr key={`${item.observation.asset?.fqdn ?? item.observation.provenance?.record_number ?? 'row'}-${index}`}>
                        <Table.Td>
                          {[
                            item.observation.asset?.fqdn,
                            item.observation.asset?.short_hostname,
                            ...(item.observation.asset?.ip_addresses ?? []),
                            ...(item.observation.asset?.native_ids ?? []).map((nativeId) => [nativeId.source, nativeId.instance, nativeId.kind, nativeId.value].filter(Boolean).join(' · ')),
                          ].filter((value, valueIndex, values) => value && values.indexOf(value) === valueIndex).join(' · ') || `Record ${item.observation.provenance?.record_number ?? index + 1}`}
                        </Table.Td>
                        <Table.Td>{[item.observation.provenance?.source, item.observation.provenance?.instance].filter(Boolean).join(' · ') || '-'}</Table.Td>
                        <Table.Td>{humanize(item.observation.kind ?? 'unknown')}</Table.Td>
                        <Table.Td>{item.observation.observed_at ?? '-'}</Table.Td>
                        <Table.Td><Badge color={item.decision.action === 'review' ? 'orange' : item.decision.action === 'create' ? 'blue' : 'green'}>{humanize(item.decision.action)}</Badge></Table.Td>
                        <Table.Td>
                          {item.decision.explanation ?? item.decision.rule ?? '-'}
                          {item.decision.candidate_ids?.length ? <Text size="xs" c="dimmed">Candidates: {item.decision.candidate_ids.join(', ')}</Text> : null}
                          {item.decision.confidence != null ? <Text size="xs" c="dimmed">Rule score: {item.decision.confidence.toFixed(2)}</Text> : null}
                        </Table.Td>
                        <Table.Td>{item.observation.warnings?.join('; ') || '-'}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            ) : <Text c="dimmed">No preview rows on this page.</Text>}
            {result.errors.length ? (
              <Alert color="orange" title={`Record errors${result.errors_truncated ? ' (list truncated)' : ''}`}>
                <Stack gap={4}>{result.errors.map((error, index) => <Text key={`${error.record_number}-${index}`} size="sm">Record {error.record_number}{error.instance ? ` · ${error.instance}` : ''}: {error.error}</Text>)}</Stack>
              </Alert>
            ) : null}
            {result.truncated ? <Text size="sm" c="dimmed">This result is paged. Review each page for the full preview.</Text> : null}
            <Group justify="space-between">
              <Text size="sm" c="dimmed">Showing {result.items.length ? result.offset + 1 : 0}–{result.offset + result.items.length} of {result.total} rows</Text>
              <Group>
                <Button variant="default" disabled={result.offset <= 0 || loading} onClick={() => void requestPreview(Math.max(0, result.offset - result.limit))}>Previous</Button>
                <Button variant="default" disabled={result.offset + result.limit >= result.total || loading} onClick={() => void requestPreview(result.offset + result.limit)}>Next</Button>
              </Group>
            </Group>
          </Stack>
        ) : null}
        <PersistentReconciliation refreshToken={persistentRefreshToken} />
      </Stack>
    </Card>
  );
}
