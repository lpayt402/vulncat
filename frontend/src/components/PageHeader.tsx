import type { ReactNode } from 'react';
import { Group, Stack, Text, Title } from '@mantine/core';

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <Group justify="space-between" align="flex-start" mb="lg" wrap="wrap">
      <Stack gap={4}>
        <Title order={1} size="h2">
          {title}
        </Title>
        <Text c="dimmed" maw={760}>
          {description}
        </Text>
      </Stack>
      {actions}
    </Group>
  );
}
