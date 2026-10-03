import { useMemo, useState } from 'react';
import {
  Alert,
  Accordion,
  Badge,
  Button,
  Checkbox,
  FileInput,
  Grid,
  Group,
  Modal,
  Paper,
  Progress,
  ScrollArea,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { IconEye, IconFileImport, IconUpload } from '@tabler/icons-react';
import { apiRequest, normalizeCollection } from '../api/client';
import type { ImportRun } from '../api/types';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { OfflinePreview } from '../components/OfflinePreview';
import { formatDate, formatNumber, humanize } from '../utils/format';
import { useAuth } from '../auth/AuthContext';

interface ImportPreview {
  source_file_id: string;
  duplicate: boolean;
  previous_import_id?: string | null;
  headers: string[];
  records: Array<Record<string, unknown>>;
  mapping_warnings?: Array<Record<string, unknown>>;
  unmapped_columns?: string[];
  truncated?: boolean;
}

const genericCanonicalFields = [
  'fqdn',
  'short_hostname',
  'ipv4_address',
  'ipv6_address',
  'operating_system',
  'plugin_id',
  'plugin_name',
  'plugin_family',
  'severity',
  'risk_factor',
  'cves',
  'port',
  'protocol',
  'service',
  'synopsis',
  'description',
  'solution',
  'plugin_output',
  'first_found',
  'last_found',
  'plugin_publication_date',
  'plugin_modification_date',
  'exploit_available',
  'scan_name',
  'scan_time',
];

const sourceTypes = [
  { value: 'tenable_csv', label: 'Scanner CSV' },
  { value: 'tenable_json', label: 'Scanner JSON' },
  { value: 'nessus_xml', label: 'Scanner XML (.nessus)' },
  { value: 'generic_csv', label: 'Generic CSV with mapping' },
];

export function ImportsPage() {
  const { user } = useAuth();
  const canImport = user?.role === 'administrator';
  const queryClient = useQueryClient();
  const [uploadOpened, upload] = useDisclosure(false);
  const [detailOpened, detail] = useDisclosure(false);
  const [selectedImport, setSelectedImport] = useState<ImportRun | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [sourceType, setSourceType] = useState('tenable_csv');
  const [completeScope, setCompleteScope] = useState(false);
  const [forceReprocess, setForceReprocess] = useState(false);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [mapping, setMapping] = useState<Record<string, string>>({});
  const [profileName, setProfileName] = useState('');
  const [shareProfile, setShareProfile] = useState(false);

  const imports = useQuery({
    queryKey: ['imports'],
    queryFn: async () =>
      normalizeCollection<ImportRun>(await apiRequest('/api/v1/imports', { csrf: true })),
    refetchInterval: (query) =>
      query.state.data?.items.some((item) => ['queued', 'running', 'processing'].includes(item.status))
        ? 3_000
        : false,
  });

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error('Select a source file.');
      const body = new FormData();
      body.append('upload', file);
      if (sourceType === 'generic_csv') {
        body.append('mapping_json', JSON.stringify(mapping));
      } else {
        body.append('source_type', sourceType);
        body.append('complete_comparable_scope', String(completeScope));
        body.append('force_reprocess', String(forceReprocess));
      }
      return apiRequest<ImportPreview | ImportRun>(
        sourceType === 'generic_csv' ? '/api/v1/imports/generic/preview' : '/api/v1/imports/upload',
        { method: 'POST', body },
      );
    },
    onSuccess: (result) => {
      if (sourceType === 'generic_csv') {
        const next = result as ImportPreview;
        setPreview(next);
      } else {
        notifications.show({ color: 'green', title: 'Import queued', message: 'The worker will process the immutable upload.' });
        void queryClient.invalidateQueries({ queryKey: ['imports'] });
        resetUpload();
      }
    },
  });

  const commitMutation = useMutation({
    mutationFn: () =>
      apiRequest<ImportRun>('/api/v1/imports/generic/commit', {
        method: 'POST',
        body: {
          source_file_id: preview?.source_file_id,
          mapping,
          profile_name: profileName.trim() || null,
          share_profile: shareProfile,
          complete_comparable_scope: completeScope,
          force_reprocess: forceReprocess,
        },
      }),
    onSuccess: () => {
      notifications.show({ color: 'green', title: 'Generic import queued', message: 'The normalized preview and mapping were committed.' });
      void queryClient.invalidateQueries({ queryKey: ['imports'] });
      resetUpload();
    },
  });

  function resetUpload() {
    setFile(null);
    setPreview(null);
    setMapping({});
    setProfileName('');
    setShareProfile(false);
    upload.close();
  }

  const normalizedColumns = useMemo(() => {
    const first = preview?.records?.[0];
    return first ? Object.keys(first) : [];
  }, [preview]);

  return (
    <>
      <PageHeader
        title="Imports"
        description="Import supported scanner formats or mapped CSV files. Track worker progress and retained source evidence."
        actions={canImport ? (
          <Button leftSection={<IconUpload size={17} />} onClick={upload.open}>
            Upload scan
          </Button>
        ) : undefined}
      />

      {canImport ? (
        <Accordion variant="separated" mb="lg">
          <Accordion.Item value="offline-reconciliation">
            <Accordion.Control>Offline reconciliation preview</Accordion.Control>
            <Accordion.Panel>
              <OfflinePreview />
            </Accordion.Panel>
          </Accordion.Item>
        </Accordion>
      ) : null}

      {imports.isLoading ? <LoadingState /> : imports.isError ? <ErrorState error={imports.error} /> : imports.data?.items.length ? (
        <Stack>
          {imports.data.items.map((item) => (
            <Paper className="vb-card" p="lg" key={item.id}>
              <Group justify="space-between" align="flex-start" wrap="wrap">
                <div>
                  <Group gap="xs">
                    <Title order={3} size="h5">{item.original_filename ?? item.source_type ?? item.id}</Title>
                    {item.duplicate || item.duplicate_of_import_id ? <Badge color="orange">Duplicate detected</Badge> : null}
                  </Group>
                  <Text size="sm" c="dimmed">
                    {humanize(item.source_type)} · requested {formatDate(item.requested_at, true)}
                  </Text>
                  {item.source_file?.sha256 ?? item.file_hash ? (
                    <Text size="xs" className="vb-mono" c="dimmed">
                      SHA-256 {item.source_file?.sha256 ?? item.file_hash}
                    </Text>
                  ) : null}
                </div>
                <Group>
                  <StatusBadge value={item.status} />
                  <Button
                    variant="subtle"
                    leftSection={<IconEye size={16} />}
                    onClick={() => {
                      void apiRequest<ImportRun>(`/api/v1/imports/${item.id}`, { csrf: true })
                        .then((full) => setSelectedImport(full))
                        .catch(() => setSelectedImport(item))
                        .finally(detail.open);
                    }}
                  >
                    Details
                  </Button>
                </Group>
              </Group>
              {['queued', 'running', 'processing'].includes(item.status) ? (
                <Progress value={item.job?.progress ?? item.progress ?? 0} animated mt="md" />
              ) : null}
              <SimpleGrid cols={{ base: 2, sm: 4, lg: 8 }} mt="md">
                {[
                  ['Included', item.included_records],
                  ['Skipped', item.skipped_records],
                  ['Unique assets', item.unique_assets],
                  ['New assets', item.new_assets],
                  ['Matched', item.matched_assets],
                  ['Ambiguous', item.ambiguous_assets],
                  ['New findings', item.new_findings],
                  ['Updated findings', item.updated_findings],
                ].map(([label, value]) => (
                  <div key={String(label)}>
                    <Text size="xs" c="dimmed">{label}</Text>
                    <Text fw={650}>{formatNumber(value as number)}</Text>
                  </div>
                ))}
              </SimpleGrid>
            </Paper>
          ))}
        </Stack>
      ) : (
        <EmptyState
          title="No scan imports"
          message={canImport ? 'Upload a supported scanner export to create the persistent host inventory.' : 'An administrator must upload the first scan.'}
        />
      )}

      <Modal opened={uploadOpened} onClose={resetUpload} title="Upload vulnerability scan" size="xl">
        <Stack>
          <Select
            label="Source format"
            description="Fixed formats: Tenable VM CSV/JSON and Nessus XML. Use Generic CSV for other mapped columns."
            data={sourceTypes}
            value={sourceType}
            onChange={(value) => {
              setSourceType(value ?? 'tenable_csv');
              setPreview(null);
            }}
          />
          <FileInput
            label="Source file"
            description="The original upload is retained unchanged and hashed for duplicate detection."
            accept=".csv,.json,.nessus,.xml,text/csv,application/json,application/xml"
            value={file}
            onChange={setFile}
            leftSection={<IconFileImport size={16} />}
            required
          />
          <Checkbox
            checked={completeScope}
            onChange={(event) => setCompleteScope(event.currentTarget.checked)}
            label="This is a complete, comparable scan scope"
            description="Only enable when the asset was verifiably included. This may permit authoritative Not Observed reconciliation, never silent remediation."
          />
          <Checkbox
            checked={forceReprocess}
            onChange={(event) => setForceReprocess(event.currentTarget.checked)}
            label="Force reprocessing for troubleshooting"
            description="Duplicate uploads remain idempotent and must not create duplicate inventory records."
          />

          {!preview ? (
            <>
              {uploadMutation.error ? <ErrorState error={uploadMutation.error} title="Upload failed" /> : null}
              <Group justify="flex-end">
                <Button variant="default" onClick={resetUpload}>Cancel</Button>
                <Button
                  disabled={!file}
                  loading={uploadMutation.isPending}
                  onClick={() => uploadMutation.mutate()}
                >
                  {sourceType === 'generic_csv' ? 'Preview mapping' : 'Upload and queue'}
                </Button>
              </Group>
            </>
          ) : (
            <Stack>
              {preview.duplicate ? (
                <Alert color="orange" title="Duplicate source file">
                  This hash was previously imported as {preview.previous_import_id ?? 'an earlier import'}. Force reprocessing only for troubleshooting.
                </Alert>
              ) : null}
              <Title order={3} size="h5">Column mapping</Title>
              <Grid>
                {genericCanonicalFields.map((field) => (
                  <Grid.Col span={{ base: 12, sm: 6 }} key={field}>
                    <Select
                      label={humanize(field)}
                      searchable
                      clearable
                      data={preview.headers}
                      value={mapping[field] ?? null}
                      onChange={(value) =>
                        setMapping((current) => {
                          const next = { ...current };
                          if (value) next[field] = value;
                          else delete next[field];
                          return next;
                        })
                      }
                    />
                  </Grid.Col>
                ))}
              </Grid>
              <Title order={3} size="h5">Normalized preview</Title>
              <Button
                variant="light"
                loading={uploadMutation.isPending}
                onClick={() => uploadMutation.mutate()}
              >
                Refresh normalized preview
              </Button>
              {preview.mapping_warnings?.length ? (
                <Alert color="orange" title={`${preview.mapping_warnings.length} mapping warning(s)`}>
                  <pre className="vb-mono" style={{ whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(preview.mapping_warnings, null, 2)}
                  </pre>
                </Alert>
              ) : null}
              {preview.records?.length ? (
                <ScrollArea>
                  <Table striped className="vb-table">
                    <Table.Thead>
                      <Table.Tr>
                        {normalizedColumns.map((column) => <Table.Th key={column}>{humanize(column)}</Table.Th>)}
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {preview.records.slice(0, 20).map((row, index) => (
                        <Table.Tr key={index}>
                          {normalizedColumns.map((column) => (
                            <Table.Td key={column}>{String(row[column] ?? '—')}</Table.Td>
                          ))}
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </ScrollArea>
              ) : (
                <EmptyState title="No normalized rows" message="The preview did not return any valid normalized rows." />
              )}
              {commitMutation.error ? <ErrorState error={commitMutation.error} title="Commit failed" /> : null}
              <TextInput
                label="Save mapping as import profile"
                description="Optional reusable profile name."
                value={profileName}
                onChange={(event) => setProfileName(event.currentTarget.value)}
              />
              <Checkbox
                checked={shareProfile}
                disabled={!profileName.trim()}
                onChange={(event) => setShareProfile(event.currentTarget.checked)}
                label="Share this import profile"
              />
              <Group justify="flex-end">
                <Button variant="default" onClick={() => setPreview(null)}>Back</Button>
                <Button
                  disabled={!mapping.plugin_id || (!mapping.severity && !mapping.risk_factor)}
                  loading={commitMutation.isPending}
                  onClick={() => commitMutation.mutate()}
                >
                  Commit import
                </Button>
              </Group>
            </Stack>
          )}
        </Stack>
      </Modal>

      <Modal opened={detailOpened} onClose={detail.close} title="Import summary" size="xl">
        {selectedImport ? (
          <Stack>
            <Group justify="space-between">
              <div>
                <Text fw={650}>{selectedImport.source_file?.original_filename ?? selectedImport.original_filename ?? selectedImport.id}</Text>
                <Text size="sm" c="dimmed">{formatDate(selectedImport.requested_at, true)}</Text>
                {selectedImport.source_file?.sha256 ? (
                  <Text size="xs" className="vb-mono" c="dimmed">
                    SHA-256 {selectedImport.source_file.sha256}
                  </Text>
                ) : null}
              </div>
              <StatusBadge value={selectedImport.status} />
            </Group>
            <SimpleGrid cols={{ base: 2, sm: 4 }}>
              {Object.entries({
                total_records: selectedImport.total_records,
                included_records: selectedImport.included_records,
                skipped_records: selectedImport.skipped_records,
                unique_assets: selectedImport.unique_assets,
                new_assets: selectedImport.new_assets,
                matched_assets: selectedImport.matched_assets,
                ambiguous_assets: selectedImport.ambiguous_assets,
                new_findings: selectedImport.new_findings,
                updated_findings: selectedImport.updated_findings,
              }).map(([label, value]) => (
                <Paper bg="gray.0" p="sm" key={label}>
                  <Text size="xs" c="dimmed">{humanize(label)}</Text>
                  <Text fw={700}>{formatNumber(value)}</Text>
                </Paper>
              ))}
            </SimpleGrid>
            <Title order={3} size="h5">Severity counts</Title>
            <Group>
              {Object.entries(selectedImport.severity_counts ?? {}).map(([severity, count]) => (
                <Badge key={severity} size="lg">{severity}: {formatNumber(count)}</Badge>
              ))}
            </Group>
            <Title order={3} size="h5">Warnings</Title>
            {[...(selectedImport.parse_warnings ?? []), ...(selectedImport.mapping_warnings ?? [])].length ? (
              <pre className="vb-mono">{JSON.stringify([...(selectedImport.parse_warnings ?? []), ...(selectedImport.mapping_warnings ?? [])], null, 2)}</pre>
            ) : <Text c="dimmed">No parse or mapping warnings.</Text>}
          </Stack>
        ) : null}
      </Modal>
    </>
  );
}
