import { Badge } from '@mantine/core';

const colors: Record<string, string> = {
  open: 'red',
  overdue: 'red',
  failed: 'red',
  ambiguous: 'orange',
  warning: 'orange',
  queued: 'blue',
  running: 'indigo',
  processing: 'indigo',
  planned: 'violet',
  in_progress: 'violet',
  mature: 'teal',
  complete: 'green',
  completed: 'green',
  remediated: 'green',
  success: 'green',
  new: 'cyan',
  new_or_maturity_deferred: 'cyan',
  not_observed: 'gray',
  deferred: 'gray',
  risk_accepted: 'gray',
};

export function StatusBadge({ value }: { value?: string | null }) {
  const normalized = (value ?? 'unknown').toLowerCase().replaceAll(' ', '_');
  return (
    <Badge variant="light" color={colors[normalized] ?? 'gray'}>
      {(value ?? 'Unknown').replaceAll('_', ' ')}
    </Badge>
  );
}
