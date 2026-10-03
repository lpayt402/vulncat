import { useMemo, useState } from 'react';
import { Badge, Group, Paper, Select, Text, TextInput } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { useQuery } from '@tanstack/react-query';
import type { ColumnDef } from '@tanstack/react-table';
import { IconSearch } from '@tabler/icons-react';
import { apiRequest, normalizeCollection, toQueryString } from '../api/client';
import type { AuditEvent } from '../api/types';
import { DataTable } from '../components/DataTable';
import { ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { formatDate } from '../utils/format';

export function AuditPage() {
  const [search, setSearch] = useState('');
  const [eventType, setEventType] = useState<string | null>(null);
  const [debouncedSearch] = useDebouncedValue(search, 350);

  const events = useQuery({
    queryKey: ['audit', debouncedSearch, eventType],
    queryFn: async () => {
      const result = normalizeCollection<AuditEvent>(
        await apiRequest(`/api/v1/audit${toQueryString({ entity_type: eventType, page_size: 100 })}`),
      );
      const needle = debouncedSearch.trim().toLowerCase();
      if (!needle) return result;
      const items = result.items.filter((event) => JSON.stringify(event).toLowerCase().includes(needle));
      return { ...result, items, total: items.length };
    },
  });

  const columns = useMemo<ColumnDef<AuditEvent>[]>(
    () => [
      { accessorKey: 'occurred_at', header: 'Occurred', cell: ({ getValue }) => formatDate(getValue<string>(), true) },
      {
        accessorKey: 'event_type',
        header: 'Event',
        cell: ({ getValue }) => <Badge variant="light">{getValue<string>()}</Badge>,
      },
      {
        id: 'actor',
        header: 'Actor',
        cell: ({ row }) => row.original.actor_username ?? row.original.actor ?? 'System',
      },
      {
        id: 'entity',
        header: 'Entity',
        cell: ({ row }) => (
          <div>
            <Text size="sm">{row.original.entity_type ?? '—'}</Text>
            {row.original.entity_id ? <Text className="vb-mono" size="xs" c="dimmed">{row.original.entity_id}</Text> : null}
          </div>
        ),
      },
      { accessorKey: 'outcome', header: 'Outcome', cell: ({ getValue }) => <StatusBadge value={getValue<string>()} /> },
      {
        accessorKey: 'details',
        header: 'Details',
        cell: ({ getValue }) => {
          const details = getValue<Record<string, unknown>>();
          return details ? (
            <Text className="vb-mono" size="xs" lineClamp={3}>
              {JSON.stringify(details)}
            </Text>
          ) : '—';
        },
      },
    ],
    [],
  );

  return (
    <>
      <PageHeader
        title="Audit history"
        description="Review imports, exports, downloads, identity decisions, status changes, and administrative actions."
      />
      <Paper className="vb-card" p="md" mb="md">
        <Group align="flex-end">
          <TextInput
            label="Search audit history"
            placeholder="Actor, entity, request, or detail"
            leftSection={<IconSearch size={17} />}
            value={search}
            onChange={(event) => setSearch(event.currentTarget.value)}
            style={{ flex: 1 }}
          />
          <Select
            label="Entity category"
            clearable
            searchable
            value={eventType}
            onChange={setEventType}
            data={[
              { value: 'import', label: 'Imports' },
              { value: 'export', label: 'Exports' },
              { value: 'identity', label: 'Identity' },
              { value: 'finding', label: 'Findings' },
              { value: 'user', label: 'Users' },
              { value: 'application_setting', label: 'Settings' },
            ]}
            w={220}
          />
        </Group>
      </Paper>
      {events.isLoading ? <LoadingState /> : events.isError ? <ErrorState error={events.error} /> : (
        <DataTable
          data={events.data?.items ?? []}
          columns={columns}
          total={events.data?.total}
          emptyTitle="No audit events"
          emptyMessage="No events match the current filters."
        />
      )}
    </>
  );
}
