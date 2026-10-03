import { Badge, Grid, Group, List, Paper, Progress, SimpleGrid, Stack, Text, ThemeIcon, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import {
  IconAlertTriangle,
  IconClock,
  IconDatabaseImport,
  IconExclamationCircle,
  IconServer,
  IconShieldCheck,
} from '@tabler/icons-react';
import { apiRequest } from '../api/client';
import type { DashboardMetrics } from '../api/types';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { formatDate, formatNumber } from '../utils/format';

function MetricCard({
  label,
  value,
  icon,
  color,
  detail,
}: {
  label: string;
  value?: number;
  icon: React.ReactNode;
  color: string;
  detail?: string;
}) {
  return (
    <Paper className="vb-card vb-metric" p="lg" radius="md">
      <Group justify="space-between" align="flex-start">
        <Stack gap={4}>
          <Text size="sm" c="dimmed" fw={600}>
            {label}
          </Text>
          <Title order={2}>{formatNumber(value)}</Title>
          {detail ? (
            <Text size="xs" c="dimmed">
              {detail}
            </Text>
          ) : null}
        </Stack>
        <ThemeIcon size="lg" variant="light" color={color}>
          {icon}
        </ThemeIcon>
      </Group>
    </Paper>
  );
}

function Distribution({
  title,
  values,
}: {
  title: string;
  values?: Record<string, number> | Array<{ name: string; count: number }>;
}) {
  const entries = (Array.isArray(values)
    ? values.map((item) => [item.name, item.count] as [string, number])
    : Object.entries(values ?? {})
  ).sort((a, b) => b[1] - a[1]);
  const max = Math.max(...entries.map(([, count]) => count), 1);
  return (
    <Paper className="vb-card" p="lg" radius="md">
      <Title order={3} size="h5" mb="md">
        {title}
      </Title>
      {entries.length ? (
        <Stack>
          {entries.slice(0, 8).map(([label, count]) => (
            <div key={label}>
              <Group justify="space-between" mb={4}>
                <Text size="sm">{label || 'Unassigned'}</Text>
                <Text size="sm" fw={600}>
                  {formatNumber(count)}
                </Text>
              </Group>
              <Progress value={(count / max) * 100} color="indigo" />
            </div>
          ))}
        </Stack>
      ) : (
        <EmptyState title="No distribution data" message="Metrics will appear after scan findings are imported." />
      )}
    </Paper>
  );
}

export function DashboardPage() {
  const query = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => apiRequest<DashboardMetrics>('/api/v1/dashboard'),
  });

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Track the host vulnerability backlog, maturity and SLA status, imports and identity review."
      />
      {query.isLoading ? <LoadingState /> : query.isError ? <ErrorState error={query.error} /> : (
        <Stack gap="lg">
          <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
            <MetricCard
              label="Tracked assets"
              value={query.data?.total_tracked_assets}
              icon={<IconServer size={20} />}
              color="indigo"
            />
            <MetricCard
              label="Open Medium assets"
              value={query.data?.assets_with_open_medium}
              icon={<IconAlertTriangle size={20} />}
              color="orange"
            />
            <MetricCard
              label="Open Low assets"
              value={query.data?.assets_with_open_low}
              icon={<IconShieldCheck size={20} />}
              color="blue"
            />
            <MetricCard
              label="Overdue findings"
              value={query.data?.overdue_findings}
              icon={<IconClock size={20} />}
              color="red"
              detail={`${formatNumber(query.data?.findings_approaching_sla ?? query.data?.sla?.approaching)} approaching SLA`}
            />
          </SimpleGrid>

          <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
            {Object.entries(query.data?.open_findings_by_severity ?? {}).map(([severity, count]) => (
              <Paper className="vb-card" p="md" key={severity}>
                <Group justify="space-between">
                  <Text fw={600}>{severity}</Text>
                  <Badge color={severity.toLowerCase() === 'medium' ? 'orange' : 'blue'} size="lg">
                    {formatNumber(count)}
                  </Badge>
                </Group>
              </Paper>
            ))}
            <Paper className="vb-card" p="md">
              <Group justify="space-between">
                <Text fw={600}>Inside maturity gate</Text>
                <Badge color="cyan" size="lg">
                  {formatNumber(
                    query.data?.findings_inside_maturity_gate ??
                      ((query.data?.maturity?.new ?? 0) + (query.data?.maturity?.deferred ?? 0)),
                  )}
                </Badge>
              </Group>
            </Paper>
            <Paper className="vb-card" p="md">
              <Group justify="space-between">
                <Text fw={600}>Mature backlog</Text>
                <Badge color="teal" size="lg">
                  {formatNumber(query.data?.findings_outside_maturity_gate ?? query.data?.maturity?.mature)}
                </Badge>
              </Group>
            </Paper>
          </SimpleGrid>

          <Grid>
            <Grid.Col span={{ base: 12, lg: 6 }}>
              <Distribution
                title="Findings by administrative team"
                values={query.data?.findings_by_administrative_team}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 6 }}>
              <Distribution
                title="Findings by maintenance group"
                values={query.data?.findings_by_maintenance_group}
              />
            </Grid.Col>
          </Grid>

          <Grid>
            <Grid.Col span={{ base: 12, lg: 7 }}>
              <Paper className="vb-card" p="lg">
                <Group justify="space-between" mb="md">
                  <Title order={3} size="h5">
                    Recent imports
                  </Title>
                  <ThemeIcon variant="light"><IconDatabaseImport size={18} /></ThemeIcon>
                </Group>
                {query.data?.recent_imports?.length ? (
                  <Stack gap="sm">
                    {query.data.recent_imports.slice(0, 6).map((item) => (
                      <Group key={item.id} justify="space-between">
                        <div>
                          <Text size="sm" fw={600}>{item.original_filename ?? item.source_type ?? item.id}</Text>
                          <Text size="xs" c="dimmed">{formatDate(item.requested_at, true)}</Text>
                        </div>
                        <StatusBadge value={item.status} />
                      </Group>
                    ))}
                  </Stack>
                ) : (
                  <EmptyState title="No imports yet" message="Upload a supported scan to populate the host inventory." />
                )}
              </Paper>
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 5 }}>
              <Paper className="vb-card" p="lg">
                <Group justify="space-between" mb="md">
                  <Title order={3} size="h5">Data quality</Title>
                  <ThemeIcon
                    variant="light"
                    color={query.data?.unresolved_identity_review_items ? 'orange' : 'green'}
                  >
                    <IconExclamationCircle size={18} />
                  </ThemeIcon>
                </Group>
                <Text fw={700} size="xl">
                  {formatNumber(query.data?.unresolved_identity_review_items)}
                </Text>
                <Text size="sm" c="dimmed" mb="md">Unresolved identity-review items</Text>
                {Array.isArray(query.data?.data_quality_warnings) && query.data.data_quality_warnings.length ? (
                  <List size="sm">
                    {query.data.data_quality_warnings.slice(0, 5).map((warning, index) => (
                      <List.Item key={index}>
                        {typeof warning === 'string' ? warning : JSON.stringify(warning)}
                      </List.Item>
                    ))}
                  </List>
                ) : typeof query.data?.data_quality_warnings === 'number' && query.data.data_quality_warnings > 0 ? (
                  <Text size="sm" c="orange">
                    {formatNumber(query.data.data_quality_warnings)} recent import warnings require review.
                  </Text>
                ) : <Text size="sm" c="dimmed">No data-quality warnings reported.</Text>}
              </Paper>
            </Grid.Col>
          </Grid>
        </Stack>
      )}
    </>
  );
}
