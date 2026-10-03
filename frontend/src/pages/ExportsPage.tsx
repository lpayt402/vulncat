import { useMemo } from 'react';
import { ActionIcon, Badge, Button, Group, Paper, Progress, Stack, Text, Tooltip } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { ColumnDef } from '@tanstack/react-table';
import { IconBan, IconDownload, IconRefresh } from '@tabler/icons-react';
import { apiRequest, downloadFromApi, normalizeCollection } from '../api/client';
import type { ExportJob } from '../api/types';
import { DataTable } from '../components/DataTable';
import { ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { formatDate, formatNumber, humanize } from '../utils/format';
import { useAuth } from '../auth/AuthContext';

export function ExportsPage() {
  const { user } = useAuth();
  const canManage = user?.role === 'administrator';
  const queryClient = useQueryClient();
  const exportsQuery = useQuery({
    queryKey: ['exports'],
    queryFn: async () => normalizeCollection<ExportJob>(await apiRequest('/api/v1/exports?page_size=100')),
    refetchInterval: (query) =>
      query.state.data?.items.some((item) => ['queued', 'running', 'processing'].includes(item.status))
        ? 3_000
        : 15_000,
  });

  const action = useMutation({
    mutationFn: ({ id, operation }: { id: string; operation: 'cancel' | 'retry' }) =>
      apiRequest(`/api/v1/exports/${id}/${operation}`, { method: 'POST' }),
    onSuccess: (_, variables) => {
      notifications.show({ color: 'green', message: `Export ${variables.operation} request accepted.` });
      void queryClient.invalidateQueries({ queryKey: ['exports'] });
    },
  });

  const columns = useMemo<ColumnDef<ExportJob>[]>(
    () => [
      {
        accessorKey: 'id',
        header: 'Export',
        cell: ({ row }) => (
          <Stack gap={2}>
            <Text className="vb-mono" fw={600} size="sm">{row.original.id}</Text>
            <Text size="xs" c="dimmed">{humanize(row.original.scope_mode)} · {row.original.output_format.toUpperCase()}</Text>
          </Stack>
        ),
      },
      {
        accessorKey: 'status',
        header: 'Status',
        cell: ({ row }) => (
          <Stack gap={5}>
            <StatusBadge value={row.original.status} />
            {canManage && ['queued', 'running', 'processing'].includes(row.original.status) ? (
              <Progress value={row.original.progress ?? 0} size="sm" w={100} animated />
            ) : null}
          </Stack>
        ),
      },
      { accessorKey: 'matched_host_count', header: 'Hosts', cell: ({ getValue }) => formatNumber(getValue<number>()) },
      { accessorKey: 'matched_finding_count', header: 'Findings', cell: ({ getValue }) => formatNumber(getValue<number>()) },
      { accessorKey: 'data_as_of', header: 'Data as of', cell: ({ getValue }) => formatDate(getValue<string>(), true) },
      { accessorKey: 'requested_at', header: 'Requested', cell: ({ getValue }) => formatDate(getValue<string>(), true) },
      {
        accessorKey: 'output_sha256',
        header: 'Artifact hash',
        cell: ({ getValue }) => {
          const value = getValue<string | null>();
          return value ? <Text className="vb-mono" size="xs">{value.slice(0, 12)}…</Text> : '—';
        },
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <Group gap={4} wrap="nowrap">
            {['completed', 'complete'].includes(row.original.status) ? (
              <Tooltip label="Download report">
                <ActionIcon
                  aria-label="Download report"
                  onClick={() =>
                    void downloadFromApi(
                      `/api/v1/exports/${row.original.id}/download`,
                      `vulncat-${row.original.id}.${row.original.output_format}`,
                    ).catch((error) =>
                      notifications.show({
                        color: 'red',
                        title: 'Download failed',
                        message: error instanceof Error ? error.message : 'Unable to download export.',
                      }),
                    )
                  }
                >
                  <IconDownload size={17} />
                </ActionIcon>
              </Tooltip>
            ) : null}
            {['queued', 'running', 'processing'].includes(row.original.status) ? (
              <Tooltip label="Cancel export">
                <ActionIcon
                  color="red"
                  variant="light"
                  aria-label="Cancel export"
                  onClick={() => action.mutate({ id: row.original.id, operation: 'cancel' })}
                >
                  <IconBan size={17} />
                </ActionIcon>
              </Tooltip>
            ) : null}
            {canManage && row.original.status === 'failed' ? (
              <Tooltip label="Retry export">
                <ActionIcon
                  color="orange"
                  variant="light"
                  aria-label="Retry export"
                  onClick={() => action.mutate({ id: row.original.id, operation: 'retry' })}
                >
                  <IconRefresh size={17} />
                </ActionIcon>
              </Tooltip>
            ) : null}
          </Group>
        ),
      },
    ],
    [action, canManage],
  );

  return (
    <>
      <PageHeader
        title="Export history"
        description="Track asynchronous report generation, failures, expiry, downloads, and content hashes."
        actions={
          <Button variant="default" leftSection={<IconRefresh size={17} />} onClick={() => void exportsQuery.refetch()}>
            Refresh
          </Button>
        }
      />
      {exportsQuery.isLoading ? <LoadingState /> : exportsQuery.isError ? (
        <ErrorState error={exportsQuery.error} />
      ) : (
        <DataTable
          data={exportsQuery.data?.items ?? []}
          columns={columns}
          total={exportsQuery.data?.total}
          emptyTitle="No exports"
          emptyMessage="Build a maintenance-window report to create a durable export record."
        />
      )}
      {exportsQuery.data?.items.some((item) => item.failure_reason) ? (
        <Stack mt="lg">
          {exportsQuery.data.items.filter((item) => item.failure_reason).map((item) => (
            <Paper className="vb-card" p="md" key={item.id}>
              <Group justify="space-between">
                <div>
                  <Text fw={600}>Export {item.id} failed</Text>
                  <Text size="sm" c="red">{item.failure_reason}</Text>
                </div>
                <Badge color="red">Failed</Badge>
              </Group>
            </Paper>
          ))}
        </Stack>
      ) : null}
    </>
  );
}
