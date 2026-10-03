import { useMemo, useState } from 'react';
import {
  ActionIcon,
  Badge,
  Button,
  Divider,
  Drawer,
  Group,
  MultiSelect,
  Paper,
  SegmentedControl,
  Select,
  Stack,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core';
import { useDisclosure, useDebouncedValue } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery } from '@tanstack/react-query';
import type { ColumnDef, RowSelectionState, SortingState } from '@tanstack/react-table';
import {
  IconAdjustments,
  IconEye,
  IconFileExport,
  IconDeviceFloppy,
  IconRefresh,
  IconSearch,
  IconSelector,
  IconX,
} from '@tabler/icons-react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { apiRequest, normalizeCollection } from '../api/client';
import type {
  AssetSummary,
  ExportJob,
  FindingScope,
  HostQuery,
  QueryPreview,
} from '../api/types';
import { DataTable } from '../components/DataTable';
import { ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { formatDate, formatNumber } from '../utils/format';

const DEFAULT_SORT: SortingState = [{ id: 'canonical_hostname', desc: false }];

function multiParam(params: URLSearchParams, key: string) {
  return params.getAll(key).filter(Boolean);
}

export function hostQueryFromSearchParams(params: URLSearchParams, sorting = DEFAULT_SORT): HostQuery {
  return {
    schema_version: 1,
    q: params.get('q') || undefined,
    ip_addresses: params.get('ip') ? [params.get('ip')!] : [],
    ip_scope: (params.get('ip_scope') as HostQuery['ip_scope']) ?? 'current',
    operating_systems: multiParam(params, 'os'),
    system_owners: multiParam(params, 'owner'),
    administrative_teams: multiParam(params, 'team'),
    environments: multiParam(params, 'environment'),
    maintenance_groups: multiParam(params, 'maintenance_group'),
    open_severities: multiParam(params, 'severity'),
    maturity_states: multiParam(params, 'maturity'),
    sla_states: multiParam(params, 'sla'),
    identity_review_state:
      (params.get('identity_review_state') as HostQuery['identity_review_state']) || undefined,
    tags: multiParam(params, 'tag').length
      ? {
          values: multiParam(params, 'tag'),
          match: (params.get('tag_match') as 'any' | 'all') ?? 'any',
        }
      : undefined,
    sort: sorting.map((entry) => ({
      field: entry.id,
      direction: entry.desc ? 'desc' : 'asc',
    })),
  };
}

function querySummary(query: HostQuery) {
  const parts: string[] = [];
  if (query.q) parts.push(`search “${query.q}”`);
  if (query.ip_addresses?.length) parts.push(`${query.ip_scope ?? 'current'} IP ${query.ip_addresses.join(', ')}`);
  if (query.administrative_teams?.length) parts.push(`teams: ${query.administrative_teams.join(', ')}`);
  if (query.system_owners?.length) parts.push(`owners: ${query.system_owners.join(', ')}`);
  if (query.environments?.length) parts.push(`environments: ${query.environments.join(', ')}`);
  if (query.maintenance_groups?.length) parts.push(`maintenance: ${query.maintenance_groups.join(', ')}`);
  if (query.tags?.values.length) parts.push(`tags ${query.tags.match}: ${query.tags.values.join(', ')}`);
  if (query.open_severities?.length) parts.push(`open ${query.open_severities.join('/')}`);
  if (query.maturity_states?.length) parts.push(`maturity: ${query.maturity_states.join(', ')}`);
  if (query.sla_states?.length) parts.push(`SLA: ${query.sla_states.join(', ')}`);
  if (query.identity_review_state) parts.push(`identity: ${query.identity_review_state.replaceAll('_', ' ')}`);
  return parts.length ? parts.join(' · ') : 'All tracked hosts';
}

export function HostsPage() {
  const { user } = useAuth();
  const canExport = user?.role === 'administrator';
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [filtersOpened, filters] = useDisclosure(false);
  const [sorting, setSorting] = useState<SortingState>(DEFAULT_SORT);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [search, setSearch] = useState(params.get('q') ?? '');
  const [debouncedSearch] = useDebouncedValue(search, 350);
  const page = Number(params.get('page') ?? 1);
  const pageSize = 25;

  const effectiveParams = useMemo(() => {
    const next = new URLSearchParams(params);
    if (debouncedSearch) next.set('q', debouncedSearch);
    else next.delete('q');
    return next;
  }, [params, debouncedSearch]);
  const hostQuery = useMemo(
    () => hostQueryFromSearchParams(effectiveParams, sorting),
    [effectiveParams, sorting],
  );

  const hosts = useQuery({
    queryKey: ['assets', hostQuery, page, pageSize],
    queryFn: async () => {
      const payload = await apiRequest<unknown>('/api/v1/assets/query', {
        method: 'POST',
        body: { query: hostQuery, page, page_size: pageSize },
      });
      return normalizeCollection<AssetSummary>(payload);
    },
  });

  const preview = useMutation({
    mutationFn: (findingScope: FindingScope) =>
      apiRequest<QueryPreview>('/api/v1/assets/query/preview', {
        method: 'POST',
        body: { query: hostQuery, finding_scope: findingScope },
      }),
  });

  const exportMutation = useMutation({
    mutationFn: (body: object) =>
      apiRequest<ExportJob>('/api/v1/exports', { method: 'POST', body }),
    onSuccess: (job) => {
      notifications.show({
        color: 'green',
        title: 'Export queued',
        message: `Export ${job.id} is being prepared from a durable host snapshot.`,
      });
      navigate('/exports');
    },
    onError: (error) => {
      notifications.show({
        color: 'red',
        title: 'Export could not be queued',
        message: error instanceof Error ? error.message.replace(/^\d+:\s*/, '') : 'Unexpected export error.',
      });
    },
  });

  const saveViewMutation = useMutation({
    mutationFn: ({ name, description }: { name: string; description?: string }) =>
      apiRequest('/api/v1/saved-views', {
        method: 'POST',
        body: {
          name,
          description: description || null,
          shared: false,
          query: hostQuery,
        },
      }),
    onSuccess: () => {
      notifications.show({ color: 'green', title: 'View saved', message: 'The normalized host query is available under Saved views.' });
    },
    onError: (error) => {
      notifications.show({
        color: 'red',
        title: 'View could not be saved',
        message: error instanceof Error ? error.message.replace(/^\d+:\s*/, '') : 'Unexpected saved-view error.',
      });
    },
  });

  const selectedIds = Object.entries(rowSelection)
    .filter(([, selected]) => selected)
    .map(([id]) => id);
  const defaultFindingScope: FindingScope = {
    severities: ['medium', 'low'],
    statuses: ['open', 'planned', 'in_progress', 'new_or_maturity_deferred'],
  };

  const columns = useMemo<ColumnDef<AssetSummary>[]>(
    () => [
      {
        accessorKey: 'canonical_hostname',
        header: 'Host',
        cell: ({ row }) => (
          <Stack gap={2}>
            <Text
              component={Link}
              to={`/hosts/${row.original.id}`}
              fw={650}
              c="indigo"
            >
              {row.original.canonical_hostname ?? 'Unnamed asset'}
            </Text>
            <Text size="xs" c="dimmed">{row.original.current_ip_addresses?.join(', ') || 'No current IP'}</Text>
          </Stack>
        ),
      },
      {
        id: 'owner_team',
        header: 'Owner / team',
        cell: ({ row }) => (
          <Stack gap={2}>
            <Text size="sm">{row.original.owner ?? row.original.system_owner ?? 'Unassigned'}</Text>
            <Text size="xs" c="dimmed">{row.original.team ?? row.original.administrative_team ?? 'No team'}</Text>
          </Stack>
        ),
      },
      { accessorKey: 'environment', header: 'Environment', cell: ({ getValue }) => getValue() || '—' },
      {
        accessorKey: 'open_medium_count',
        header: 'Medium',
        cell: ({ row }) => <Badge color="orange" variant="light">{formatNumber(row.original.open_medium_count ?? row.original.medium_count)}</Badge>,
      },
      {
        accessorKey: 'open_low_count',
        header: 'Low',
        cell: ({ row }) => <Badge color="blue" variant="light">{formatNumber(row.original.open_low_count ?? row.original.low_count)}</Badge>,
      },
      {
        accessorKey: 'mature_backlog_count',
        header: 'Mature',
        cell: ({ getValue }) => formatNumber(getValue<number>()),
      },
      {
        accessorKey: 'new_deferred_count',
        header: 'New / deferred',
        cell: ({ getValue }) => formatNumber(getValue<number>()),
      },
      {
        accessorKey: 'overdue_count',
        header: 'Overdue',
        cell: ({ getValue }) => (
          <Text c={Number(getValue()) > 0 ? 'red' : undefined} fw={Number(getValue()) > 0 ? 700 : 400}>
            {formatNumber(getValue<number>())}
          </Text>
        ),
      },
      {
        accessorKey: 'last_scan_observed_at',
        header: 'Last observed',
        cell: ({ getValue }) => formatDate(getValue<string>()),
      },
      {
        accessorKey: 'identity_confidence',
        header: 'Identity',
        cell: ({ row }) => (
          <Badge
            color={row.original.unresolved_identity || row.original.identity_review_state?.includes('unresolved') ? 'orange' : 'green'}
            variant="light"
          >
            {row.original.unresolved_identity || row.original.identity_review_state?.includes('unresolved')
              ? 'Review'
              : row.original.identity_confidence != null
                ? `${Math.round(row.original.identity_confidence * 100)}%`
                : 'Unknown'}
          </Badge>
        ),
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <Tooltip label="Open host">
            <ActionIcon component={Link} to={`/hosts/${row.original.id}`} variant="subtle" aria-label="Open host">
              <IconEye size={18} />
            </ActionIcon>
          </Tooltip>
        ),
      },
    ],
    [],
  );

  function updateFilter(key: string, values: string[]) {
    const next = new URLSearchParams(params);
    next.delete(key);
    values.filter(Boolean).forEach((value) => next.append(key, value));
    next.delete('page');
    setParams(next);
  }

  const activeChips = [
    ...(hostQuery.administrative_teams ?? []).map((value) => ['Team', value] as const),
    ...(hostQuery.system_owners ?? []).map((value) => ['Owner', value] as const),
    ...(hostQuery.environments ?? []).map((value) => ['Environment', value] as const),
    ...(hostQuery.maintenance_groups ?? []).map((value) => ['Maintenance', value] as const),
    ...(hostQuery.tags?.values ?? []).map((value) => ['Tag', value] as const),
    ...(hostQuery.open_severities ?? []).map((value) => ['Severity', value] as const),
    ...(hostQuery.maturity_states ?? []).map((value) => ['Maturity', value] as const),
    ...(hostQuery.sla_states ?? []).map((value) => ['SLA', value] as const),
  ];

  return (
    <>
      <PageHeader
        title="Hosts"
        description="Filter canonical assets. Select rows on this page or export all assets matching the filter."
        actions={
          <Group>
            <Button
              variant="default"
              leftSection={<IconDeviceFloppy size={17} />}
              loading={saveViewMutation.isPending}
              onClick={() => {
                const name = window.prompt('Name for this private saved host view:');
                if (!name?.trim()) return;
                const description = window.prompt('Optional description:') ?? '';
                saveViewMutation.mutate({ name: name.trim(), description: description.trim() });
              }}
            >
              Save view
            </Button>
            <Button variant="default" leftSection={<IconAdjustments size={17} />} onClick={filters.open}>
              Filters
            </Button>
            <Button
              variant="light"
              leftSection={<IconRefresh size={17} />}
              onClick={() => void hosts.refetch()}
            >
              Refresh
            </Button>
          </Group>
        }
      />

      <Paper className="vb-card" p="md" mb="md">
        <Stack gap="sm">
          <Group align="flex-end">
            <TextInput
              label="Search hosts"
              placeholder="Hostname, alias, IP, or asset identifier"
              leftSection={<IconSearch size={17} />}
              value={search}
              onChange={(event) => {
                setSearch(event.currentTarget.value);
                const next = new URLSearchParams(params);
                next.delete('page');
                setParams(next, { replace: true });
              }}
              style={{ flex: 1 }}
            />
            <Select
              label="Rows"
              value={String(pageSize)}
              data={['25']}
              disabled
              w={90}
            />
          </Group>
          <Text size="sm" c="dimmed">
            {querySummary(hostQuery)}
          </Text>
          {activeChips.length ? (
            <Group gap="xs">
              {activeChips.map(([label, value]) => (
                <Badge key={`${label}-${value}`} variant="light">
                  {label}: {value}
                </Badge>
              ))}
              <Button
                size="compact-xs"
                variant="subtle"
                color="gray"
                leftSection={<IconX size={13} />}
                onClick={() => {
                  setParams(new URLSearchParams(search ? { q: search } : {}));
                }}
              >
                Clear filters
              </Button>
            </Group>
          ) : null}
        </Stack>
      </Paper>

      {hosts.isLoading ? <LoadingState /> : hosts.isError ? <ErrorState error={hosts.error} /> : (
        <DataTable
          data={hosts.data?.items ?? []}
          columns={columns}
          total={hosts.data?.total}
          page={page}
          pageSize={pageSize}
          onPageChange={(nextPage) => {
            const next = new URLSearchParams(params);
            next.set('page', String(nextPage));
            setParams(next);
          }}
          sorting={sorting}
          onSortingChange={(next) => {
            setSorting(next);
            setRowSelection({});
          }}
          selectable
          rowSelection={rowSelection}
          onRowSelectionChange={setRowSelection}
          toolbar={
            <Group justify="space-between" wrap="wrap">
              <Group>
                <IconSelector size={18} />
                <Text size="sm">
                  <strong>{selectedIds.length}</strong> selected on loaded pages
                </Text>
              </Group>
              <Group>
                <Button
                  variant="default"
                  leftSection={<IconFileExport size={17} />}
                  disabled={!canExport || !selectedIds.length}
                  loading={exportMutation.isPending}
                  onClick={() =>
                    exportMutation.mutate({
                      asset_scope: { mode: 'selected_assets', asset_ids: selectedIds },
                      finding_scope: defaultFindingScope,
                      format: 'xlsx',
                    })
                  }
                >
                  Export selected hosts
                </Button>
                <Button
                  leftSection={<IconFileExport size={17} />}
                  disabled={!canExport}
                  loading={preview.isPending || exportMutation.isPending}
                  onClick={async () => {
                    const result = await preview.mutateAsync(defaultFindingScope);
                    if (!result.matching_host_count) {
                      notifications.show({
                        color: 'orange',
                        title: 'No matching hosts',
                        message: 'Adjust the query before creating an export.',
                      });
                      return;
                    }
                    if (
                      !window.confirm(
                        `Export all ${result.matching_host_count.toLocaleString()} matching hosts across every page?`,
                      )
                    ) {
                      return;
                    }
                    exportMutation.mutate({
                      asset_scope: { mode: 'host_query', query: result.normalized_query },
                      finding_scope: defaultFindingScope,
                      format: 'xlsx',
                      confirm_large_export: true,
                    });
                  }}
                >
                  Export all {formatNumber(hosts.data?.total)} matching
                </Button>
              </Group>
            </Group>
          }
        />
      )}

      <Drawer opened={filtersOpened} onClose={filters.close} title="Host filters" position="right" size="md">
        <Stack>
          <TextInput
            label="IP address"
            placeholder="10.20.30.40 or 2001:db8::1"
            value={params.get('ip') ?? ''}
            onChange={(event) => {
              const next = new URLSearchParams(params);
              if (event.currentTarget.value) next.set('ip', event.currentTarget.value);
              else next.delete('ip');
              setParams(next);
            }}
          />
          <SegmentedControl
            fullWidth
            value={params.get('ip_scope') ?? 'current'}
            data={[
              { value: 'current', label: 'Current IP' },
              { value: 'history', label: 'Historical' },
              { value: 'both', label: 'Both' },
            ]}
            onChange={(value) => {
              const next = new URLSearchParams(params);
              next.set('ip_scope', value);
              setParams(next);
            }}
          />
          <MultiSelect
            label="Administrative teams"
            placeholder="Enter team names"
            searchable
            data={multiParam(params, 'team')}
            value={multiParam(params, 'team')}
            onChange={(values) => updateFilter('team', values)}
          />
          <MultiSelect
            label="Owners"
            placeholder="Enter owners"
            searchable
            data={multiParam(params, 'owner')}
            value={multiParam(params, 'owner')}
            onChange={(values) => updateFilter('owner', values)}
          />
          <MultiSelect
            label="Environments"
            placeholder="production, staging…"
            searchable
            data={multiParam(params, 'environment')}
            value={multiParam(params, 'environment')}
            onChange={(values) => updateFilter('environment', values)}
          />
          <MultiSelect
            label="Maintenance groups"
            placeholder="mw-03…"
            searchable
            data={multiParam(params, 'maintenance_group')}
            value={multiParam(params, 'maintenance_group')}
            onChange={(values) => updateFilter('maintenance_group', values)}
          />
          <MultiSelect
            label="Tags"
            placeholder="pci, internet-facing…"
            searchable
            data={multiParam(params, 'tag')}
            value={multiParam(params, 'tag')}
            onChange={(values) => updateFilter('tag', values)}
          />
          <SegmentedControl
            fullWidth
            value={params.get('tag_match') ?? 'any'}
            data={[
              { value: 'any', label: 'Any tag' },
              { value: 'all', label: 'All tags' },
            ]}
            onChange={(value) => {
              const next = new URLSearchParams(params);
              next.set('tag_match', value);
              setParams(next);
            }}
          />
          <MultiSelect
            label="Open severities"
            data={[
              { value: 'medium', label: 'Medium' },
              { value: 'low', label: 'Low' },
            ]}
            value={multiParam(params, 'severity')}
            onChange={(values) => updateFilter('severity', values)}
          />
          <MultiSelect
            label="Maturity state"
            data={[
              { value: 'mature', label: 'Mature' },
              { value: 'new_or_maturity_deferred', label: 'New or deferred' },
            ]}
            value={multiParam(params, 'maturity')}
            onChange={(values) => updateFilter('maturity', values)}
          />
          <MultiSelect
            label="SLA state"
            data={[
              { value: 'overdue', label: 'Overdue' },
              { value: 'approaching', label: 'Approaching' },
              { value: 'within_sla', label: 'Within SLA' },
            ]}
            value={multiParam(params, 'sla')}
            onChange={(values) => updateFilter('sla', values)}
          />
          <Select
            label="Identity review state"
            clearable
            data={[
              { value: 'exclude_unresolved', label: 'Exclude unresolved' },
              { value: 'only_unresolved', label: 'Only unresolved' },
              { value: 'include_unresolved', label: 'Include unresolved' },
            ]}
            value={params.get('identity_review_state')}
            onChange={(value) => {
              const next = new URLSearchParams(params);
              if (value) next.set('identity_review_state', value);
              else next.delete('identity_review_state');
              setParams(next);
            }}
          />
          <Divider />
          <Text size="sm" c="dimmed">
            Active query: {querySummary(hostQuery)}
          </Text>
          <Button onClick={filters.close}>Apply filters</Button>
        </Stack>
      </Drawer>
    </>
  );
}
