import { useState } from 'react';
import {
  Badge,
  Button,
  Checkbox,
  Group,
  Modal,
  Paper,
  Stack,
  Text,
  Textarea,
  TextInput,
  Title,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { IconExternalLink, IconFileExport, IconPlus, IconTrash } from '@tabler/icons-react';
import { Link, useNavigate } from 'react-router-dom';
import { apiRequest } from '../api/client';
import type { ExportJob, HostQuery, SavedView } from '../api/types';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { formatDate } from '../utils/format';
import { useAuth } from '../auth/AuthContext';

const blankQuery: HostQuery = {
  schema_version: 1,
  identity_review_state: 'include_unresolved',
  sort: [{ field: 'canonical_hostname', direction: 'asc' }],
} as HostQuery;

export function SavedViewsPage() {
  const { user } = useAuth();
  const canExport = user?.role === 'administrator';
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [opened, setOpened] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [shared, setShared] = useState(false);
  const [queryJson, setQueryJson] = useState(JSON.stringify(blankQuery, null, 2));

  const views = useQuery({
    queryKey: ['saved-views'],
    queryFn: () => apiRequest<SavedView[]>('/api/v1/saved-views'),
  });

  const create = useMutation({
    mutationFn: () =>
      apiRequest<SavedView>('/api/v1/saved-views', {
        method: 'POST',
        body: {
          name,
          description: description || null,
          shared,
          query: JSON.parse(queryJson),
        },
      }),
    onSuccess: () => {
      notifications.show({ color: 'green', message: 'Saved view created.' });
      void queryClient.invalidateQueries({ queryKey: ['saved-views'] });
      setOpened(false);
      setName('');
      setDescription('');
      setShared(false);
      setQueryJson(JSON.stringify(blankQuery, null, 2));
    },
  });

  const remove = useMutation({
    mutationFn: (viewId: string) =>
      apiRequest(`/api/v1/saved-views/${viewId}`, { method: 'DELETE' }),
    onSuccess: () => {
      notifications.show({ color: 'green', message: 'Saved view deleted.' });
      void queryClient.invalidateQueries({ queryKey: ['saved-views'] });
    },
  });

  const exportView = useMutation({
    mutationFn: (viewId: string) =>
      apiRequest<ExportJob>('/api/v1/exports', {
        method: 'POST',
        body: {
          asset_scope: { mode: 'saved_view', saved_view_id: viewId },
          finding_scope: {
            schema_version: 1,
            severities: ['medium', 'low'],
            statuses: ['open', 'new_or_maturity_deferred', 'planned', 'in_progress'],
          },
          format: 'xlsx',
          confirm_large_export: false,
        },
      }),
    onSuccess: () => {
      notifications.show({ color: 'green', message: 'Saved-view export queued.' });
      navigate('/exports');
    },
  });

  return (
    <>
      <PageHeader
        title="Saved views"
        description="Save versioned host queries for personal use or share them with other users."
        actions={
          <Button leftSection={<IconPlus size={17} />} onClick={() => setOpened(true)}>
            New saved view
          </Button>
        }
      />
      {views.isLoading ? <LoadingState /> : views.isError ? <ErrorState error={views.error} /> : views.data?.length ? (
        <Stack>
          {views.data.map((view) => (
            <Paper className="vb-card" p="lg" key={view.id}>
              <Group justify="space-between" align="flex-start" wrap="wrap">
                <div>
                  <Group gap="xs">
                    <Title order={3} size="h5">{view.name}</Title>
                    <Badge color={view.shared ? 'indigo' : 'gray'}>{view.shared ? 'Shared' : 'Private'}</Badge>
                    <Badge variant="outline">Revision {view.revision}</Badge>
                  </Group>
                  <Text size="sm" c="dimmed">{view.description || 'No description'}</Text>
                  <Text size="xs" c="dimmed" mt={4}>
                    Query schema v{view.query_schema_version} · updated {formatDate(view.updated_at, true)}
                  </Text>
                </div>
                <Group>
                  <Button
                    component={Link}
                    to={`/hosts?q=${encodeURIComponent((view.query ?? view.query_json)?.q ?? '')}`}
                    variant="default"
                    leftSection={<IconExternalLink size={16} />}
                  >
                    Open hosts
                  </Button>
                  <Button
                    variant="light"
                    leftSection={<IconFileExport size={16} />}
                    disabled={!canExport}
                    loading={exportView.isPending}
                    onClick={() => exportView.mutate(view.id)}
                  >
                    Export view
                  </Button>
                  <Button
                    variant="subtle"
                    color="red"
                    leftSection={<IconTrash size={16} />}
                    loading={remove.isPending}
                    onClick={() => {
                      if (window.confirm(`Delete saved view “${view.name}”?`)) remove.mutate(view.id);
                    }}
                  >
                    Delete
                  </Button>
                </Group>
              </Group>
              <Paper bg="gray.0" p="sm" mt="md">
                <pre className="vb-mono" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
                  {JSON.stringify(view.query ?? view.query_json, null, 2)}
                </pre>
              </Paper>
            </Paper>
          ))}
        </Stack>
      ) : (
        <EmptyState title="No saved views" message="Save a normalized host query for repeatable operations and reports." />
      )}

      <Modal opened={opened} onClose={() => setOpened(false)} title="Create saved view" size="lg">
        <Stack>
          <TextInput label="Name" value={name} onChange={(event) => setName(event.currentTarget.value)} required />
          <Textarea label="Description" value={description} onChange={(event) => setDescription(event.currentTarget.value)} />
          <Checkbox
            checked={shared}
            disabled={user?.role !== 'administrator'}
            onChange={(event) => setShared(event.currentTarget.checked)}
            label="Share with other users"
            description={user?.role === 'administrator' ? 'Shared views are visible to all signed-in users.' : 'Only administrators may create shared views.'}
          />
          <Textarea
            label="Versioned host query JSON"
            autosize
            minRows={12}
            className="vb-mono"
            value={queryJson}
            onChange={(event) => setQueryJson(event.currentTarget.value)}
          />
          {create.error ? <ErrorState error={create.error} title="Unable to save view" /> : null}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setOpened(false)}>Cancel</Button>
            <Button
              disabled={!name.trim()}
              loading={create.isPending}
              onClick={() => {
                try {
                  JSON.parse(queryJson);
                  create.mutate();
                } catch {
                  notifications.show({ color: 'red', message: 'Query JSON is invalid.' });
                }
              }}
            >
              Save view
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
