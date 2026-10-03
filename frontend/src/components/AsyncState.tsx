import { Alert, Center, Loader, Stack, Text, ThemeIcon } from '@mantine/core';
import { IconAlertTriangle, IconDatabaseOff } from '@tabler/icons-react';

export function LoadingState({ label = 'Loading data…' }: { label?: string }) {
  return (
    <Center py="xl">
      <Stack align="center" gap="sm">
        <Loader size="sm" />
        <Text c="dimmed" size="sm">
          {label}
        </Text>
      </Stack>
    </Center>
  );
}

export function ErrorState({ error, title = 'Unable to load data' }: { error: unknown; title?: string }) {
  const message = error instanceof Error ? error.message.replace(/^\d+:\s*/, '') : 'Unexpected error';
  return (
    <Alert color="red" title={title} icon={<IconAlertTriangle size={18} />}>
      {message}
    </Alert>
  );
}

export function EmptyState({
  title,
  message,
}: {
  title: string;
  message: string;
}) {
  return (
    <Center className="vb-empty" p="xl">
      <Stack align="center" gap="xs">
        <ThemeIcon color="gray" variant="light" size="xl">
          <IconDatabaseOff size={22} />
        </ThemeIcon>
        <Text fw={600}>{title}</Text>
        <Text c="dimmed" size="sm" ta="center" maw={520}>
          {message}
        </Text>
      </Stack>
    </Center>
  );
}
