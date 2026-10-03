import { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Checkbox,
  Divider,
  Group,
  MultiSelect,
  Paper,
  Radio,
  Select,
  SimpleGrid,
  Stack,
  Text,
  Textarea,
  TextInput,
  Title,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery } from '@tanstack/react-query';
import { IconFileAnalytics, IconReportSearch } from '@tabler/icons-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { apiRequest } from '../api/client';
import type {
  ExportJob,
  FindingScope,
  HostQuery,
  QueryPreview,
  SavedView,
} from '../api/types';
import { ErrorState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { formatNumber } from '../utils/format';

const defaultQuery: HostQuery = {
  schema_version: 1,
  ip_scope: 'current',
  identity_review_state: 'include_unresolved',
  sort: [{ field: 'canonical_hostname', direction: 'asc' }],
} as HostQuery;

const defaultFindingScope: FindingScope = {
  schema_version: 1,
  severities: ['medium', 'low'],
  statuses: ['open', 'new_or_maturity_deferred', 'planned', 'in_progress'],
} as FindingScope;

export function ReportBuilderPage() {
  const { user } = useAuth();
  const canExport = user?.role === 'administrator';
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [mode, setMode] = useState<'host_query' | 'selected_assets' | 'saved_view'>(
    searchParams.get('saved_view_id') ? 'saved_view' : 'host_query',
  );
  const [q, setQ] = useState('');
  const [teams, setTeams] = useState<string[]>([]);
  const [environments, setEnvironments] = useState<string[]>([]);
  const [maintenanceGroups, setMaintenanceGroups] = useState<string[]>([]);
  const [tags, setTags] = useState<string[]>([]);
  const [tagMatch, setTagMatch] = useState<'any' | 'all'>('any');
  const [selectedAssetIds, setSelectedAssetIds] = useState('');
  const [savedViewId, setSavedViewId] = useState(searchParams.get('saved_view_id') ?? '');
  const [format, setFormat] = useState<'xlsx' | 'csv' | 'html'>('xlsx');
  const [severities, setSeverities] = useState<string[]>(['medium', 'low']);
  const [maturityStates, setMaturityStates] = useState<string[]>([]);
  const [slaStates, setSlaStates] = useState<string[]>([]);
  const [statuses, setStatuses] = useState<string[]>(defaultFindingScope.statuses ?? []);
  const [confirmLarge, setConfirmLarge] = useState(false);
  const [previewResult, setPreviewResult] = useState<QueryPreview | null>(null);

  const savedViews = useQuery({
    queryKey: ['saved-views'],
    queryFn: () => apiRequest<SavedView[]>('/api/v1/saved-views'),
  });

  const hostQuery: HostQuery = useMemo(
    () => ({
      ...defaultQuery,
      q: q || undefined,
      administrative_teams: teams,
      environments,
      maintenance_groups: maintenanceGroups,
      tags: tags.length ? { values: tags, match: tagMatch } : undefined,
    }),
    [q, teams, environments, maintenanceGroups, tags, tagMatch],
  );
  const findingScope: FindingScope = useMemo(
    () => ({
      ...defaultFindingScope,
      severities,
      maturity_states: maturityStates,
      sla_states: slaStates,
      statuses,
    }),
    [severities, maturityStates, slaStates, statuses],
  );

  const preview = useMutation({
    mutationFn: () =>
      apiRequest<QueryPreview>('/api/v1/assets/query/preview', {
        method: 'POST',
        body: { query: hostQuery, finding_scope: findingScope },
      }),
    onSuccess: setPreviewResult,
  });

  const createExport = useMutation({
    mutationFn: () => {
      const assetScope =
        mode === 'host_query'
          ? { mode, query: previewResult?.normalized_query ?? hostQuery }
          : mode === 'saved_view'
            ? { mode, saved_view_id: savedViewId }
            : {
                mode,
                asset_ids: selectedAssetIds
                  .split(/[\s,]+/)
                  .map((value) => value.trim())
                  .filter(Boolean),
              };
      return apiRequest<ExportJob>('/api/v1/exports', {
        method: 'POST',
        body: {
          asset_scope: assetScope,
          finding_scope: findingScope,
          format,
          confirm_large_export: confirmLarge,
        },
      });
    },
    onSuccess: (job) => {
      notifications.show({
        color: 'green',
        title: 'Report queued',
        message: `Export ${job.id} will be generated from its persisted asset and finding snapshot.`,
      });
      navigate('/exports');
    },
  });

  const canSubmit =
    severities.length > 0 &&
    (mode === 'host_query'
      ? Boolean(previewResult?.matching_host_count)
      : mode === 'saved_view'
        ? Boolean(savedViewId)
        : selectedAssetIds.split(/[\s,]+/).filter(Boolean).length > 0);

  return (
    <>
      <PageHeader
        title="Maintenance-window report builder"
        description="Choose hosts and finding filters, then generate XLSX, CSV or printable HTML from a saved snapshot."
      />
      {!canExport ? (
        <Alert color="blue" mb="md">
          Your account can review report scope and export history, but only administrators may submit new exports.
        </Alert>
      ) : null}
      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Paper className="vb-card" p="lg">
          <Title order={2} size="h4" mb="md">1. Host scope</Title>
          <Radio.Group value={mode} onChange={(value) => {
            setMode(value as typeof mode);
            setPreviewResult(null);
          }}>
            <Stack>
              <Radio value="host_query" label="All hosts matching an ad hoc query" />
              <Radio value="selected_assets" label="Explicit canonical asset UUIDs" />
              <Radio value="saved_view" label="Named saved host view" />
            </Stack>
          </Radio.Group>
          <Divider my="lg" />

          {mode === 'host_query' ? (
            <Stack>
              <TextInput
                label="Host search"
                placeholder="Hostname, alias, IP, or identifier"
                value={q}
                onChange={(event) => {
                  setQ(event.currentTarget.value);
                  setPreviewResult(null);
                }}
              />
              <MultiSelect
                label="Administrative teams"
                searchable
                data={teams}
                value={teams}
                onChange={(value) => {
                  setTeams(value);
                  setPreviewResult(null);
                }}
              />
              <MultiSelect
                label="Environments"
                searchable
                data={environments}
                value={environments}
                onChange={(value) => {
                  setEnvironments(value);
                  setPreviewResult(null);
                }}
              />
              <MultiSelect
                label="Maintenance groups"
                searchable
                data={maintenanceGroups}
                value={maintenanceGroups}
                onChange={(value) => {
                  setMaintenanceGroups(value);
                  setPreviewResult(null);
                }}
              />
              <MultiSelect
                label="Tags"
                searchable
                data={tags}
                value={tags}
                onChange={(value) => {
                  setTags(value);
                  setPreviewResult(null);
                }}
              />
              <Radio.Group value={tagMatch} onChange={(value) => {
                setTagMatch(value as 'any' | 'all');
                setPreviewResult(null);
              }} label="Tag semantics">
                <Group mt="xs">
                  <Radio value="any" label="Match any tag" />
                  <Radio value="all" label="Match all tags" />
                </Group>
              </Radio.Group>
              <Button
                variant="light"
                leftSection={<IconReportSearch size={17} />}
                loading={preview.isPending}
                onClick={() => preview.mutate()}
              >
                Preview host query
              </Button>
              {preview.error ? <ErrorState error={preview.error} title="Preview failed" /> : null}
              {previewResult ? (
                <Alert
                  color={previewResult.matching_host_count ? 'blue' : 'orange'}
                  title={`${formatNumber(previewResult.matching_host_count)} matching hosts`}
                >
                  <Text size="sm">
                    Approximately {formatNumber(previewResult.estimated_matching_finding_count ?? previewResult.matching_finding_count)} finding rows match the selected finding scope.
                  </Text>
                  {previewResult.warnings?.map((warning, index) => (
                    <Text size="sm" key={index}>
                      {typeof warning === 'string' ? warning : warning.message}
                    </Text>
                  ))}
                </Alert>
              ) : null}
            </Stack>
          ) : mode === 'selected_assets' ? (
            <Textarea
              label="Canonical asset UUIDs"
              description="Enter one UUID per line or separate values with commas."
              minRows={9}
              value={selectedAssetIds}
              onChange={(event) => setSelectedAssetIds(event.currentTarget.value)}
              className="vb-mono"
            />
          ) : (
            <Select
              label="Saved view"
              searchable
              data={(savedViews.data ?? []).map((view) => ({
                value: view.id,
                label: `${view.name} · revision ${view.revision}${view.shared ? ' · shared' : ''}`,
              }))}
              value={savedViewId}
              onChange={(value) => setSavedViewId(value ?? '')}
              error={savedViews.error ? 'Unable to load saved views' : undefined}
            />
          )}
        </Paper>

        <Paper className="vb-card" p="lg">
          <Title order={2} size="h4" mb="md">2. Finding scope and output</Title>
          <Stack>
            <MultiSelect
              label="Tracked severities"
              data={['medium', 'low']}
              value={severities}
              onChange={setSeverities}
              required
            />
            <MultiSelect
              label="Maturity states"
              description="Leave empty to include every maturity state."
              data={['new', 'deferred', 'mature', 'unknown']}
              value={maturityStates}
              onChange={setMaturityStates}
            />
            <MultiSelect
              label="SLA states"
              description="Leave empty to include every SLA state."
              data={['not_due', 'approaching', 'overdue', 'unknown']}
              value={slaStates}
              onChange={setSlaStates}
            />
            <MultiSelect
              label="Finding statuses"
              data={['open', 'new_or_maturity_deferred', 'planned', 'in_progress', 'not_observed', 'remediated', 'risk_accepted', 'false_positive', 'not_applicable']}
              value={statuses}
              onChange={setStatuses}
            />
            <Select
              label="Output format"
              data={[
                { value: 'xlsx', label: 'XLSX workbook' },
                { value: 'csv', label: 'CSV package' },
                { value: 'html', label: 'Printable HTML' },
              ]}
              value={format}
              onChange={(value) => setFormat((value ?? 'xlsx') as typeof format)}
            />
            {format === 'xlsx' ? (
              <Alert color="indigo" title="Workbook contents" icon={<IconFileAnalytics size={18} />}>
                Host Summary, Finding Detail, and Export Metadata sheets will be generated from the same durable snapshot.
              </Alert>
            ) : null}
            <Checkbox
              checked={confirmLarge}
              onChange={(event) => setConfirmLarge(event.currentTarget.checked)}
              label="Confirm unusually large export"
              description="Enable only after reviewing the preview warning and host/finding counts."
            />
            <Divider />
            <Text size="sm" c="dimmed">
              Export submission persists the normalized query, full canonical-asset set, finding scope, data-as-of timestamp, requester, counts, and artifact hash.
            </Text>
            {createExport.error ? <ErrorState error={createExport.error} title="Export submission failed" /> : null}
            <Button
              size="md"
              disabled={!canExport || !canSubmit}
              loading={createExport.isPending}
              onClick={() => {
                if (canExport) createExport.mutate();
              }}
            >
              Generate maintenance-window report
            </Button>
          </Stack>
        </Paper>
      </SimpleGrid>
    </>
  );
}
