import { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  NumberInput,
  Paper,
  SimpleGrid,
  Stack,
  Switch,
  TextInput,
  Title,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiRequest, toQueryString } from '../api/client';
import type { AppSetting } from '../api/types';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { humanize } from '../utils/format';
import { useAuth } from '../auth/AuthContext';

const numericSettings = new Set([
  'maturity_gate_days',
  'medium_sla_days',
  'low_sla_days',
  'ip_association_staleness_days',
  'session_timeout_minutes',
  'upload_max_bytes',
  'large_export_finding_threshold',
  'upload_retention_days',
  'import_evidence_retention_days',
  'audit_retention_days',
  'report_retention_days',
]);

function parseSetting(value: string, original: unknown) {
  if (typeof original === 'number') return Number(value);
  if (typeof original === 'boolean') return value === 'true';
  if (Array.isArray(original)) return value.split(',').map((entry) => entry.trim()).filter(Boolean);
  try {
    if (typeof original === 'object' && original !== null) return JSON.parse(value);
  } catch {
    return value;
  }
  return value;
}

export function SettingsPage() {
  const { user } = useAuth();
  const canEdit = user?.role === 'administrator';
  const queryClient = useQueryClient();
  const [edits, setEdits] = useState<Record<string, string>>({});

  const settings = useQuery({
    queryKey: ['settings'],
    queryFn: async () => {
      const response = await apiRequest<{
        effective: Record<string, unknown>;
        stored_overrides: Record<string, unknown>;
      }>('/api/v1/settings');
      return Object.entries(response.effective).map(([key, value]) => ({
        key,
        value: response.stored_overrides[key] ?? value,
        description: response.stored_overrides[key] !== undefined ? 'Stored override; service restart may be required.' : 'Effective application value.',
      }));
    },
  });

  const update = useMutation({
    mutationFn: (setting: AppSetting) =>
      apiRequest<AppSetting>(
        `/api/v1/settings/${encodeURIComponent(setting.key)}${toQueryString({
          value: parseSetting(edits[setting.key] ?? String(setting.value ?? ''), setting.value),
        })}`,
        { method: 'PUT' },
      ),
    onSuccess: (setting) => {
      notifications.show({ color: 'green', message: `${humanize(setting.key)} updated.` });
      void queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
  });

  const grouped = useMemo(() => {
    const items = settings.data ?? [];
    return {
      lifecycle: items.filter((item) => /maturity|sla|first_found/i.test(item.key)),
      identity: items.filter((item) => /identity|association|staleness|confidence/i.test(item.key)),
      security: items.filter((item) => /session|login|upload|max/i.test(item.key)),
      retention: items.filter((item) => /retention|expiry|expire/i.test(item.key)),
      export: items.filter((item) => /export|report|threshold/i.test(item.key)),
      other: items.filter((item) => !/maturity|sla|first_found|identity|association|staleness|confidence|session|login|upload|max|retention|expiry|expire|export|report|threshold/i.test(item.key)),
    };
  }, [settings.data]);

  function SettingsGroup({ title, items }: { title: string; items: AppSetting[] }) {
    if (!items.length) return null;
    return (
      <Paper className="vb-card" p="lg">
        <Title order={2} size="h4" mb="md">{title}</Title>
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          {items.map((setting) => {
            const value = edits[setting.key] ?? (
              typeof setting.value === 'object' ? JSON.stringify(setting.value) : String(setting.value ?? '')
            );
            return (
              <Paper bg="gray.0" p="md" key={setting.key}>
                <Stack gap="xs">
                  {typeof setting.value === 'boolean' ? (
                    <Switch
                      label={humanize(setting.key)}
                      description={setting.description}
                      checked={value === 'true'}
                      disabled={!canEdit}
                      onChange={(event) =>
                        setEdits((current) => ({ ...current, [setting.key]: String(event.currentTarget.checked) }))
                      }
                    />
                  ) : numericSettings.has(setting.key) || typeof setting.value === 'number' ? (
                    <NumberInput
                      label={humanize(setting.key)}
                      description={setting.description}
                      value={Number(value)}
                      min={0}
                      disabled={!canEdit}
                      onChange={(next) =>
                        setEdits((current) => ({ ...current, [setting.key]: String(next) }))
                      }
                    />
                  ) : (
                    <TextInput
                      label={humanize(setting.key)}
                      description={setting.description}
                      value={value}
                      disabled={!canEdit}
                      onChange={(event) =>
                        setEdits((current) => ({ ...current, [setting.key]: event.currentTarget.value }))
                      }
                    />
                  )}
                  {canEdit ? (
                    <Button
                      size="xs"
                      variant="light"
                      disabled={edits[setting.key] === undefined}
                      loading={update.isPending && update.variables?.key === setting.key}
                      onClick={() => update.mutate(setting)}
                    >
                      Save setting
                    </Button>
                  ) : null}
                </Stack>
              </Paper>
            );
          })}
        </SimpleGrid>
      </Paper>
    );
  }

  return (
    <>
      <PageHeader
        title="Application settings"
        description="Manage maturity and SLA clocks, identity safeguards, security limits, retention, and large-export thresholds."
      />
      {!canEdit ? <Alert color="blue" mb="md">Settings are read-only for your role.</Alert> : null}
      {settings.isLoading ? <LoadingState /> : settings.isError ? <ErrorState error={settings.error} /> : settings.data?.length ? (
        <Stack>
          <SettingsGroup title="Finding maturity and SLA" items={grouped.lifecycle} />
          <SettingsGroup title="Asset identity safeguards" items={grouped.identity} />
          <SettingsGroup title="Security and upload limits" items={grouped.security} />
          <SettingsGroup title="Retention" items={grouped.retention} />
          <SettingsGroup title="Exports" items={grouped.export} />
          <SettingsGroup title="Other settings" items={grouped.other} />
        </Stack>
      ) : (
        <EmptyState title="No settings returned" message="Application defaults are active, but the API did not return editable settings." />
      )}
    </>
  );
}
