import { useMemo, useState } from 'react';
import {
  Accordion,
  ActionIcon,
  Alert,
  Badge,
  Button,
  Divider,
  Grid,
  Group,
  Modal,
  Paper,
  ScrollArea,
  SimpleGrid,
  Stack,
  Table,
  Tabs,
  Text,
  Textarea,
  TextInput,
  Title,
  Tooltip,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  IconArrowLeft,
  IconArrowsExchange,
  IconCheck,
  IconCut,
  IconGitMerge,
  IconHistory,
  IconNetwork,
  IconNotes,
  IconShare,
} from '@tabler/icons-react';
import { Link, useParams } from 'react-router-dom';
import { apiRequest } from '../api/client';
import type { AssetDetail, AssetIdentifier } from '../api/types';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { formatDate, getTagNames, humanize } from '../utils/format';
import { useAuth } from '../auth/AuthContext';

export function HostDetailPage() {
  const { assetId = '' } = useParams();
  const { user } = useAuth();
  const canEdit = user?.role === 'administrator';
  const queryClient = useQueryClient();
  const [editOpened, edit] = useDisclosure(false);
  const [mergeOpened, merge] = useDisclosure(false);
  const [mergeTarget, setMergeTarget] = useState('');
  const [mergeReason, setMergeReason] = useState('');

  const assetQuery = useQuery({
    queryKey: ['asset', assetId],
    queryFn: () => apiRequest<AssetDetail>(`/api/v1/assets/${assetId}`),
    enabled: Boolean(assetId),
  });

  const updateAsset = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest<AssetDetail>(`/api/v1/assets/${assetId}`, { method: 'PATCH', body }),
    onSuccess: (asset) => {
      queryClient.setQueryData(['asset', assetId], asset);
      notifications.show({ color: 'green', message: 'Host metadata updated.' });
      edit.close();
    },
  });

  const identifierAction = useMutation({
    mutationFn: ({
      identifierId,
      action,
      reason,
    }: {
      identifierId: string;
      action: 'verify' | 'mark-shared';
      reason: string;
    }) =>
      apiRequest(`/api/v1/identity/identifiers/${identifierId}/${action}`, {
        method: 'POST',
        body: { reason },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['asset', assetId] });
      notifications.show({ color: 'green', message: 'Identifier decision recorded.' });
    },
  });

  const identifierStructuralAction = useMutation({
    mutationFn: ({
      identifierId,
      action,
      body,
    }: {
      identifierId: string;
      action: 'move' | 'split';
      body: Record<string, unknown>;
    }) =>
      apiRequest(`/api/v1/identity/identifiers/${identifierId}/${action}`, {
        method: 'POST',
        body,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['asset', assetId] });
      notifications.show({ color: 'green', message: 'Identifier change recorded as a reversible identity event.' });
    },
  });

  const mergePreview = useMutation({
    mutationFn: () =>
      apiRequest('/api/v1/identity/merge/preview', {
        method: 'POST',
        body: {
          source_asset_id: mergeTarget,
          target_asset_id: assetId,
          reason: mergeReason,
        },
      }),
  });

  const mergeAssets = useMutation({
    mutationFn: () =>
      apiRequest('/api/v1/identity/merge', {
        method: 'POST',
        body: {
          source_asset_id: mergeTarget,
          target_asset_id: assetId,
          reason: mergeReason,
        },
      }),
    onSuccess: () => {
      notifications.show({ color: 'green', message: 'Assets merged and the reversible identity event was recorded.' });
      merge.close();
      setMergeTarget('');
      setMergeReason('');
      mergePreview.reset();
      void queryClient.invalidateQueries({ queryKey: ['asset', assetId] });
    },
  });

  const asset = assetQuery.data;
  const currentIpAddresses = (asset?.identifiers ?? [])
    .filter((identifier) => identifier.active && ['ipv4', 'ipv6'].includes(identifier.type ?? identifier.identifier_type ?? ''))
    .map((identifier) => identifier.normalized_value);
  const historicalIpAddresses = (asset?.identifiers ?? [])
    .filter((identifier) => !identifier.active && ['ipv4', 'ipv6'].includes(identifier.type ?? identifier.identifier_type ?? ''))
    .map((identifier) => identifier.normalized_value);
  const editValues = useMemo(
    () => ({
      system_owner: asset?.system_owner ?? asset?.owner ?? '',
      administrative_team: asset?.administrative_team ?? asset?.team ?? '',
      technical_owner: asset?.technical_owner ?? '',
      environment: asset?.environment ?? '',
      data_center: asset?.data_center ?? '',
      business_service: asset?.business_service ?? '',
      server_role: asset?.server_role ?? '',
      maintenance_group: asset?.maintenance_group ?? '',
      patch_group: asset?.patch_group ?? '',
      notes: asset?.notes ?? '',
    }),
    [asset],
  );

  if (assetQuery.isLoading) return <LoadingState label="Loading host details…" />;
  if (assetQuery.isError) return <ErrorState error={assetQuery.error} title="Unable to load host" />;
  if (!asset) return <EmptyState title="Host not found" message="The canonical asset does not exist." />;

  return (
    <>
      <PageHeader
        title={asset.canonical_hostname ?? 'Unnamed asset'}
        description="Canonical identity, historical evidence, vulnerability backlog, ownership, and change history."
        actions={
          <Group>
            <Button component={Link} to="/hosts" variant="default" leftSection={<IconArrowLeft size={17} />}>
              Hosts
            </Button>
            {canEdit ? (
              <>
                <Button variant="default" leftSection={<IconGitMerge size={17} />} onClick={merge.open}>
                  Preview merge
                </Button>
                <Button onClick={edit.open}>Edit metadata</Button>
              </>
            ) : null}
          </Group>
        }
      />

      {asset.identity_review_state?.includes('unresolved') ? (
        <Alert color="orange" title="Identity review required" mb="md">
          This asset has unresolved identity evidence. Review it before relying on weak identifiers for reconciliation.
        </Alert>
      ) : null}

      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} mb="lg">
        {[
          ['Current IPs', asset.current_ip_addresses?.join(', ') || currentIpAddresses.join(', ') || '—'],
          ['Operating system', asset.operating_system || '—'],
          ['Owner / team', `${asset.system_owner ?? asset.owner ?? 'Unassigned'} / ${asset.administrative_team ?? asset.team ?? 'Unassigned'}`],
          ['Last observed', formatDate(asset.last_scan_observed_at, true)],
        ].map(([label, value]) => (
          <Paper className="vb-card" p="lg" key={label}>
            <Text size="xs" tt="uppercase" fw={700} c="dimmed">{label}</Text>
            <Text fw={650} mt={6}>{value}</Text>
          </Paper>
        ))}
      </SimpleGrid>

      <Tabs defaultValue="findings">
        <Tabs.List>
          <Tabs.Tab value="findings" leftSection={<IconNetwork size={16} />}>Open findings</Tabs.Tab>
          <Tabs.Tab value="identity" leftSection={<IconHistory size={16} />}>Identity and identifiers</Tabs.Tab>
          <Tabs.Tab value="classification">Ownership and classification</Tabs.Tab>
          <Tabs.Tab value="history">Evidence and history</Tabs.Tab>
          <Tabs.Tab value="notes" leftSection={<IconNotes size={16} />}>Notes</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="findings" pt="md">
          <Paper className="vb-card">
            {asset.findings?.length ? (
              <ScrollArea>
                <Table striped highlightOnHover className="vb-table">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Plugin</Table.Th>
                      <Table.Th>Severity</Table.Th>
                      <Table.Th>Port</Table.Th>
                      <Table.Th>Maturity</Table.Th>
                      <Table.Th>SLA</Table.Th>
                      <Table.Th>First found</Table.Th>
                      <Table.Th>Status</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {asset.findings.map((finding) => (
                      <Table.Tr key={finding.id}>
                        <Table.Td>
                          <Text fw={600}>{finding.plugin_name ?? `Plugin ${finding.plugin_id}`}</Text>
                          <Text size="xs" c="dimmed">{finding.plugin_family ?? 'Unknown family'} · {finding.plugin_id}</Text>
                        </Table.Td>
                        <Table.Td><StatusBadge value={finding.severity} /></Table.Td>
                        <Table.Td>{finding.port ?? 0}/{finding.protocol ?? 'general'}</Table.Td>
                        <Table.Td><StatusBadge value={finding.maturity_status} /></Table.Td>
                        <Table.Td><StatusBadge value={finding.sla_status} /></Table.Td>
                        <Table.Td>{formatDate(finding.first_found_at ?? finding.first_seen_at)}</Table.Td>
                        <Table.Td><StatusBadge value={finding.status} /></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            ) : (
              <div style={{ padding: 16 }}>
                <EmptyState title="No tracked findings" message="No Medium or Low finding rows were returned for this asset." />
              </div>
            )}
          </Paper>
        </Tabs.Panel>

        <Tabs.Panel value="identity" pt="md">
          <Paper className="vb-card" p="lg">
            <Title order={3} size="h5" mb="md">Known identifiers</Title>
            {asset.identifiers?.length ? (
              <Table className="vb-table">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Type</Table.Th>
                    <Table.Th>Value</Table.Th>
                    <Table.Th>Observed</Table.Th>
                    <Table.Th>Confidence</Table.Th>
                    <Table.Th>State</Table.Th>
                    <Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {asset.identifiers.map((identifier: AssetIdentifier) => (
                    <Table.Tr key={identifier.id}>
                      <Table.Td>{humanize(identifier.identifier_type ?? identifier.type)}</Table.Td>
                      <Table.Td className="vb-mono">{identifier.normalized_value}</Table.Td>
                      <Table.Td>{formatDate(identifier.first_observed_at)} – {formatDate(identifier.last_observed_at)}</Table.Td>
                      <Table.Td>{identifier.confidence != null ? `${Math.round(identifier.confidence * 100)}%` : '—'}</Table.Td>
                      <Table.Td>
                        <Group gap={4}>
                          {identifier.manually_verified ? <Badge color="green">Verified</Badge> : null}
                          {identifier.shared_or_non_identifying ? <Badge color="orange">Non-identifying</Badge> : null}
                          {!identifier.active ? <Badge color="gray">Historical</Badge> : null}
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        {canEdit ? (
                          <Group gap={4} wrap="nowrap">
                            <Tooltip label="Verify association">
                              <ActionIcon
                                variant="light"
                                color="green"
                                aria-label="Verify association"
                                onClick={() => {
                                  const reason = window.prompt('Reason for verifying this identifier association:');
                                  if (reason?.trim()) identifierAction.mutate({ identifierId: identifier.id, action: 'verify', reason });
                                }}
                              >
                                <IconCheck size={16} />
                              </ActionIcon>
                            </Tooltip>
                            {['ipv4', 'ipv6'].includes(identifier.type ?? identifier.identifier_type ?? '') ? (
                            <Tooltip label="Mark shared or non-identifying">
                              <ActionIcon
                                variant="light"
                                color="orange"
                                aria-label="Mark shared"
                                onClick={() => {
                                  const reason = window.prompt('Reason for treating this IP as shared or non-identifying:');
                                  if (reason?.trim()) identifierAction.mutate({ identifierId: identifier.id, action: 'mark-shared', reason });
                                }}
                              >
                                <IconShare size={16} />
                              </ActionIcon>
                            </Tooltip>
                            ) : null}
                            <Tooltip label="Move identifier to another asset">
                              <ActionIcon
                                variant="light"
                                color="blue"
                                aria-label="Move identifier"
                                onClick={() => {
                                  const targetAssetId = window.prompt('Target canonical asset UUID:');
                                  if (!targetAssetId?.trim()) return;
                                  const reason = window.prompt('Reason for moving this identifier:');
                                  if (reason?.trim()) {
                                    identifierStructuralAction.mutate({
                                      identifierId: identifier.id,
                                      action: 'move',
                                      body: { target_asset_id: targetAssetId.trim(), reason },
                                    });
                                  }
                                }}
                              >
                                <IconArrowsExchange size={16} />
                              </ActionIcon>
                            </Tooltip>
                            <Tooltip label="Split identifier into a new asset">
                              <ActionIcon
                                variant="light"
                                color="violet"
                                aria-label="Split identifier"
                                onClick={() => {
                                  const canonicalHostname = window.prompt('Canonical hostname for the new asset (optional):') ?? '';
                                  const reason = window.prompt('Reason for splitting this identifier:');
                                  if (reason?.trim()) {
                                    identifierStructuralAction.mutate({
                                      identifierId: identifier.id,
                                      action: 'split',
                                      body: { canonical_hostname: canonicalHostname.trim() || null, reason },
                                    });
                                  }
                                }}
                              >
                                <IconCut size={16} />
                              </ActionIcon>
                            </Tooltip>
                          </Group>
                        ) : null}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            ) : <EmptyState title="No identifiers" message="No identifier evidence was returned for this asset." />}
            <Divider my="lg" />
            <Grid>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <Text fw={600} mb="xs">Known aliases</Text>
                <Text>{asset.known_aliases?.join(', ') || '—'}</Text>
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 6 }}>
                <Text fw={600} mb="xs">Historical IP addresses</Text>
                <Text>{asset.historical_ip_addresses?.join(', ') || historicalIpAddresses.join(', ') || '—'}</Text>
              </Grid.Col>
            </Grid>
          </Paper>
        </Tabs.Panel>

        <Tabs.Panel value="classification" pt="md">
          <Paper className="vb-card" p="lg">
            <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }}>
              {[
                ['System owner', asset.system_owner ?? asset.owner],
                ['Administrative team', asset.administrative_team ?? asset.team],
                ['Technical owner', asset.technical_owner],
                ['Environment', asset.environment],
                ['Data center', asset.data_center],
                ['Business service', asset.business_service],
                ['Server role', asset.server_role],
                ['Maintenance group', asset.maintenance_group],
                ['Patch group', asset.patch_group],
              ].map(([label, value]) => (
                <div key={label}>
                  <Text size="xs" c="dimmed" tt="uppercase" fw={700}>{label}</Text>
                  <Text mt={4}>{value || '—'}</Text>
                </div>
              ))}
            </SimpleGrid>
            <Divider my="lg" />
            <Text size="xs" c="dimmed" tt="uppercase" fw={700}>Tags</Text>
            <Group mt="xs">
              {getTagNames(asset.tags).length ? getTagNames(asset.tags).map((tag) => <Badge key={tag}>{tag}</Badge>) : <Text>—</Text>}
            </Group>
          </Paper>
        </Tabs.Panel>

        <Tabs.Panel value="history" pt="md">
          <Stack>
            <Paper className="vb-card" p="lg">
              <Title order={3} size="h5" mb="md">Import history</Title>
              {asset.import_history?.length ? (
                <Accordion>
                  {asset.import_history.map((item) => (
                    <Accordion.Item key={item.id} value={item.id}>
                      <Accordion.Control>{item.original_filename ?? item.source_type ?? item.id}</Accordion.Control>
                      <Accordion.Panel>
                        <Text size="sm">Status: {item.status} · Requested {formatDate(item.requested_at, true)}</Text>
                      </Accordion.Panel>
                    </Accordion.Item>
                  ))}
                </Accordion>
              ) : <EmptyState title="No import history" message="No source import history was returned." />}
            </Paper>
            <Paper className="vb-card" p="lg">
              <Title order={3} size="h5" mb="md">Merge and split history</Title>
              {asset.identity_history?.length ? (
                <Accordion>
                  {asset.identity_history.map((event, index) => (
                    <Accordion.Item key={String(event.id ?? index)} value={String(event.id ?? index)}>
                      <Accordion.Control>{humanize(String(event.event_type ?? 'identity event'))}</Accordion.Control>
                      <Accordion.Panel>
                        <pre className="vb-mono">{JSON.stringify(event, null, 2)}</pre>
                      </Accordion.Panel>
                    </Accordion.Item>
                  ))}
                </Accordion>
              ) : <EmptyState title="No identity changes" message="No merge or split events were returned." />}
            </Paper>
          </Stack>
        </Tabs.Panel>

        <Tabs.Panel value="notes" pt="md">
          <Paper className="vb-card" p="lg">
            <Text style={{ whiteSpace: 'pre-wrap' }}>{asset.notes || 'No asset notes have been recorded.'}</Text>
          </Paper>
        </Tabs.Panel>
      </Tabs>

      <Modal opened={editOpened} onClose={edit.close} title="Edit host metadata" size="lg">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            updateAsset.mutate(Object.fromEntries(form.entries()));
          }}
        >
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            {Object.entries(editValues).filter(([key]) => key !== 'notes').map(([key, value]) => (
              <TextInput key={key} name={key} label={humanize(key)} defaultValue={value} />
            ))}
          </SimpleGrid>
          <Textarea name="notes" label="Notes" defaultValue={editValues.notes} minRows={4} mt="md" />
          <Group justify="flex-end" mt="lg">
            <Button variant="default" onClick={edit.close}>Cancel</Button>
            <Button type="submit" loading={updateAsset.isPending}>Save changes</Button>
          </Group>
        </form>
      </Modal>

      <Modal opened={mergeOpened} onClose={merge.close} title="Preview asset merge">
        <Stack>
          <Alert color="orange">
            A preview is required before any merge. Stronger conflicting identifiers must not be silently overridden.
          </Alert>
          <TextInput
            label="Source asset UUID"
            value={mergeTarget}
            onChange={(event) => setMergeTarget(event.currentTarget.value)}
            placeholder="Asset to merge into this canonical host"
          />
          <Textarea
            label="Merge reason"
            value={mergeReason}
            onChange={(event) => setMergeReason(event.currentTarget.value)}
            minRows={3}
            required
          />
          <Button
            disabled={!mergeTarget || mergeReason.trim().length < 3}
            loading={mergePreview.isPending}
            onClick={() => mergePreview.mutate()}
          >
            Generate merge preview
          </Button>
          {mergePreview.data ? (
            <>
              <Paper bg="gray.0" p="sm">
                <pre className="vb-mono" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(mergePreview.data, null, 2)}</pre>
              </Paper>
              <Button
                color="orange"
                loading={mergeAssets.isPending}
                onClick={() => {
                  if (window.confirm('Merge the source asset into this canonical host using the reviewed preview?')) {
                    mergeAssets.mutate();
                  }
                }}
              >
                Merge source into this host
              </Button>
            </>
          ) : null}
          {mergePreview.error ? <ErrorState error={mergePreview.error} /> : null}
          {mergeAssets.error ? <ErrorState error={mergeAssets.error} /> : null}
        </Stack>
      </Modal>
    </>
  );
}
