import { useMemo, useState } from 'react';
import {
  Badge,
  Group,
  MultiSelect,
  Paper,
  SegmentedControl,
  Stack,
  Text,
  TextInput,
} from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { useQuery } from '@tanstack/react-query';
import type { ColumnDef, SortingState } from '@tanstack/react-table';
import { IconSearch } from '@tabler/icons-react';
import { Link, useSearchParams } from 'react-router-dom';
import { apiRequest, normalizeCollection, toQueryString } from '../api/client';
import type { FindingSummary, PluginSummary } from '../api/types';
import { DataTable } from '../components/DataTable';
import { ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { formatDate, formatNumber } from '../utils/format';

export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const view = params.get('view') ?? 'host';
  const [search, setSearch] = useState(params.get('q') ?? '');
  const [debouncedSearch] = useDebouncedValue(search, 350);
  const [sorting, setSorting] = useState<SortingState>([{ id: 'last_seen_at', desc: true }]);
  const page = Number(params.get('page') ?? 1);

  const query = useQuery({
    queryKey: ['findings', view, params.toString(), debouncedSearch, sorting],
    queryFn: async () => {
      const payload = await apiRequest(
        `${view === 'plugin' ? '/api/v1/findings/plugins' : '/api/v1/findings'}${toQueryString({
          page,
          page_size: 30,
          q: debouncedSearch,
          severity: params.getAll('severity'),
          finding_status: params.getAll('status'),
          maturity_state: params.getAll('maturity'),
          sla_state: params.getAll('sla'),
          environment: params.getAll('environment'),
          maintenance_group: params.getAll('maintenance_group'),
          plugin_id: params.get('plugin_id'),
          cve: params.get('cve'),
          port: params.get('port'),
        })}`,
      );
      return view === 'plugin'
        ? normalizeCollection<PluginSummary & { id?: string }>(payload)
        : normalizeCollection<FindingSummary>(payload);
    },
  });

  function updateMulti(key: string, values: string[]) {
    const next = new URLSearchParams(params);
    next.delete(key);
    values.forEach((value) => next.append(key, value));
    next.delete('page');
    setParams(next);
  }

  const findingColumns = useMemo<ColumnDef<FindingSummary>[]>(
    () => [
      {
        accessorKey: 'canonical_hostname',
        header: 'Host',
        cell: ({ row }) => row.original.asset_id ? (
          <Text component={Link} to={`/hosts/${row.original.asset_id}`} fw={600} c="indigo">
            {row.original.canonical_hostname ?? 'Unnamed asset'}
          </Text>
        ) : row.original.canonical_hostname ?? '—',
      },
      {
        accessorKey: 'plugin_id',
        header: 'Plugin',
        cell: ({ row }) => (
          <Stack gap={2}>
            <Text fw={600}>{row.original.plugin_name ?? `Plugin ${row.original.plugin_id}`}</Text>
            <Text size="xs" c="dimmed">{row.original.plugin_family ?? 'Unknown family'} · {row.original.plugin_id}</Text>
          </Stack>
        ),
      },
      { accessorKey: 'severity', header: 'Severity', cell: ({ getValue }) => <StatusBadge value={getValue<string>()} /> },
      {
        id: 'network',
        header: 'Port',
        cell: ({ row }) => `${row.original.port ?? 0}/${row.original.protocol ?? 'general'}`,
      },
      { accessorKey: 'maturity_status', header: 'Maturity', cell: ({ getValue }) => <StatusBadge value={getValue<string>()} /> },
      { accessorKey: 'sla_status', header: 'SLA', cell: ({ getValue }) => <StatusBadge value={getValue<string>()} /> },
      { accessorKey: 'last_seen_at', header: 'Last seen', cell: ({ getValue }) => formatDate(getValue<string>()) },
      { accessorKey: 'status', header: 'Status', cell: ({ getValue }) => <StatusBadge value={getValue<string>()} /> },
    ],
    [],
  );

  const pluginColumns = useMemo<ColumnDef<PluginSummary & { id?: string }>[]>(
    () => [
      {
        accessorKey: 'plugin_id',
        header: 'Plugin',
        cell: ({ row }) => (
          <Stack gap={2}>
            <Text fw={650}>{row.original.plugin_name ?? `Plugin ${row.original.plugin_id}`}</Text>
            <Text size="xs" c="dimmed">{row.original.plugin_id}</Text>
          </Stack>
        ),
      },
      { accessorKey: 'severity', header: 'Severity', cell: ({ getValue }) => <StatusBadge value={getValue<string>()} /> },
      {
        accessorKey: 'cves',
        header: 'CVEs',
        cell: ({ getValue }) => (getValue<string[]>() ?? []).join(', ') || '—',
      },
      {
        accessorKey: 'affected_host_count',
        header: 'Affected hosts',
        cell: ({ getValue }) => <Badge>{formatNumber(getValue<number>())}</Badge>,
      },
      {
        accessorKey: 'owners',
        header: 'Owners / teams',
        cell: ({ row }) => [...(row.original.owners ?? []), ...(row.original.teams ?? [])].join(', ') || '—',
      },
      { accessorKey: 'first_observed_at', header: 'First observed', cell: ({ getValue }) => formatDate(getValue<string>()) },
      { accessorKey: 'last_observed_at', header: 'Last observed', cell: ({ getValue }) => formatDate(getValue<string>()) },
    ],
    [],
  );

  return (
    <>
      <PageHeader
        title="Findings"
        description="Review the persistent Medium and Low backlog by canonical host or scanner plugin."
        actions={
          <SegmentedControl
            value={view}
            data={[
              { value: 'host', label: 'Host centered' },
              { value: 'plugin', label: 'Plugin centered' },
            ]}
            onChange={(value) => {
              const next = new URLSearchParams(params);
              next.set('view', value);
              next.delete('page');
              setParams(next);
            }}
          />
        }
      />
      <Paper className="vb-card" p="md" mb="md">
        <Stack>
          <TextInput
            label="Search findings"
            placeholder="Plugin, CVE, hostname, or IP"
            leftSection={<IconSearch size={17} />}
            value={search}
            onChange={(event) => setSearch(event.currentTarget.value)}
          />
          <Group grow align="flex-start">
            <MultiSelect
              label="Severity"
              data={['medium', 'low']}
              value={params.getAll('severity')}
              onChange={(values) => updateMulti('severity', values)}
            />
            <MultiSelect
              label="Status"
              data={['open', 'new_or_maturity_deferred', 'planned', 'in_progress', 'not_observed', 'remediated', 'risk_accepted', 'false_positive', 'not_applicable']}
              value={params.getAll('status')}
              onChange={(values) => updateMulti('status', values)}
            />
            <MultiSelect
              label="Maturity"
              data={['mature', 'new_or_maturity_deferred']}
              value={params.getAll('maturity')}
              onChange={(values) => updateMulti('maturity', values)}
            />
            <MultiSelect
              label="SLA"
              data={['within_sla', 'approaching', 'overdue']}
              value={params.getAll('sla')}
              onChange={(values) => updateMulti('sla', values)}
            />
          </Group>
        </Stack>
      </Paper>
      {query.isLoading ? <LoadingState /> : query.isError ? <ErrorState error={query.error} /> : view === 'plugin' ? (
        <DataTable
          data={(query.data?.items ?? []) as Array<PluginSummary & { id?: string }>}
          columns={pluginColumns}
          total={query.data?.total}
          page={page}
          pageSize={30}
          onPageChange={(nextPage) => {
            const next = new URLSearchParams(params);
            next.set('page', String(nextPage));
            setParams(next);
          }}
          sorting={sorting}
          onSortingChange={setSorting}
        />
      ) : (
        <DataTable
          data={(query.data?.items ?? []) as FindingSummary[]}
          columns={findingColumns}
          total={query.data?.total}
          page={page}
          pageSize={30}
          onPageChange={(nextPage) => {
            const next = new URLSearchParams(params);
            next.set('page', String(nextPage));
            setParams(next);
          }}
          sorting={sorting}
          onSortingChange={setSorting}
        />
      )}
    </>
  );
}
