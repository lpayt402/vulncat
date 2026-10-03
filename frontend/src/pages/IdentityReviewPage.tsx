import { useState } from 'react';
import {
  Alert,
  Button,
  Group,
  Modal,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Text,
  Textarea,
  Title,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { IconShieldCheck } from '@tabler/icons-react';
import { apiRequest, normalizeCollection } from '../api/client';
import type { IdentityReviewItem } from '../api/types';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { formatDate, humanize } from '../utils/format';
import { useAuth } from '../auth/AuthContext';

const actions = [
  { value: 'match_existing', label: 'Match to existing asset' },
  { value: 'create_asset', label: 'Create new asset' },
  { value: 'mark_shared', label: 'Mark identifier shared / non-identifying' },
  { value: 'reject', label: 'Reject proposed association' },
  { value: 'defer', label: 'Defer decision' },
];

export function IdentityReviewPage() {
  const { user } = useAuth();
  const canResolve = user?.role === 'administrator';
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<IdentityReviewItem | null>(null);
  const [action, setAction] = useState<string | null>(null);
  const [targetAssetId, setTargetAssetId] = useState('');
  const [reason, setReason] = useState('');

  const items = useQuery({
    queryKey: ['identity-review'],
    queryFn: async () =>
      normalizeCollection<IdentityReviewItem>(
        await apiRequest('/api/v1/identity/review?review_status=open'),
      ),
  });

  const resolve = useMutation({
    mutationFn: () =>
      apiRequest(`/api/v1/identity/review/${selected?.id}/resolve`, {
        method: 'POST',
        body: {
          action,
          asset_id: targetAssetId || undefined,
          reason,
        },
      }),
    onSuccess: () => {
      notifications.show({ color: 'green', title: 'Decision recorded', message: 'The manual identity override will take precedence over later automatic matching.' });
      setSelected(null);
      setAction(null);
      setTargetAssetId('');
      setReason('');
      void queryClient.invalidateQueries({ queryKey: ['identity-review'] });
    },
  });

  return (
    <>
      <PageHeader
        title="Identity Review Queue"
        description="Resolve ambiguous asset associations without allowing weak evidence to silently merge canonical hosts."
      />
      {!canResolve ? (
        <Alert color="blue" mb="md">Read-only users can review evidence but cannot record identity decisions.</Alert>
      ) : null}
      {items.isLoading ? <LoadingState /> : items.isError ? <ErrorState error={items.error} /> : items.data?.items.length ? (
        <Stack>
          {items.data.items.map((item) => (
            <Paper className="vb-card" p="lg" key={item.id}>
              <Group justify="space-between" align="flex-start" wrap="wrap">
                <div>
                  <Group gap="xs">
                    <Title order={3} size="h5">{item.explanation ?? 'Ambiguous identity association'}</Title>
                    <StatusBadge value={item.status} />
                  </Group>
                  <Text size="sm" c="dimmed">
                    Rule: {humanize(item.matching_rule)} · Confidence {item.confidence != null ? `${Math.round(item.confidence * 100)}%` : 'unknown'}
                  </Text>
                  <Text size="xs" c="dimmed">
                    Observed {formatDate(item.first_observed_at)} – {formatDate(item.last_observed_at)}
                  </Text>
                </div>
                <Button
                  variant={canResolve ? 'filled' : 'default'}
                  leftSection={<IconShieldCheck size={17} />}
                  onClick={() => {
                    void apiRequest<IdentityReviewItem>(`/api/v1/identity/review/${item.id}`)
                      .then(setSelected)
                      .catch(() => setSelected(item));
                  }}
                >
                  {canResolve ? 'Review and resolve' : 'Review evidence'}
                </Button>
              </Group>
              <SimpleGrid cols={{ base: 1, md: 3 }} mt="lg">
                <Paper bg="gray.0" p="sm">
                  <Text fw={650} size="sm">Incoming identifiers</Text>
                  <pre className="vb-mono" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(item.incoming_identifiers ?? [], null, 2)}</pre>
                </Paper>
                <Paper bg="gray.0" p="sm">
                  <Text fw={650} size="sm">Candidate assets</Text>
                  <Stack gap={4} mt="xs">
                    {(item.candidate_assets ?? []).map((asset) => (
                      <Text size="sm" key={asset.id}>{asset.canonical_hostname ?? asset.id}</Text>
                    ))}
                    {!item.candidate_assets?.length ? (
                      <Text size="sm">{item.candidate_asset_ids?.join(', ') || 'None returned'}</Text>
                    ) : null}
                  </Stack>
                </Paper>
                <Paper bg="gray.0" p="sm">
                  <Text fw={650} size="sm">Conflicting evidence</Text>
                  <pre className="vb-mono" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(item.conflicting_evidence ?? [], null, 2)}</pre>
                </Paper>
              </SimpleGrid>
            </Paper>
          ))}
        </Stack>
      ) : (
        <EmptyState title="Identity queue is clear" message="No unresolved ambiguous associations were returned." />
      )}

      <Modal opened={Boolean(selected)} onClose={() => setSelected(null)} title="Identity decision" size="lg">
        {selected ? (
          <Stack>
            <Alert color="orange">
              Strong identifiers take priority. Preview merges and record a reason so the decision remains auditable and reversible where supported.
            </Alert>
            <pre className="vb-mono" style={{ whiteSpace: 'pre-wrap' }}>
              {JSON.stringify({
                incoming_identifiers: selected.incoming_identifiers,
                candidate_assets: selected.candidate_asset_ids,
                conflicting_evidence: selected.conflicting_evidence,
                matching_rule: selected.matching_rule,
                source_import_id: selected.source_import_id,
              }, null, 2)}
            </pre>
            {canResolve ? (
              <>
                <Select label="Resolution" data={actions} value={action} onChange={setAction} required />
                {action === 'match_existing' ? (
                  <Select
                    label="Target asset"
                    searchable
                    data={(selected.candidate_assets ?? []).map((asset) => ({
                      value: asset.id,
                      label: asset.canonical_hostname ?? asset.id,
                    }))}
                    value={targetAssetId}
                    onChange={(value) => setTargetAssetId(value ?? '')}
                    required
                  />
                ) : null}
                <Textarea label="Decision reason" minRows={3} value={reason} onChange={(event) => setReason(event.currentTarget.value)} required />
                {resolve.error ? <ErrorState error={resolve.error} title="Resolution failed" /> : null}
                <Button disabled={!action || !reason.trim()} loading={resolve.isPending} onClick={() => resolve.mutate()}>
                  Record decision
                </Button>
              </>
            ) : null}
          </Stack>
        ) : null}
      </Modal>
    </>
  );
}
