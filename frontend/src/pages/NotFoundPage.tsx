import { Button, Center, Stack, Text, Title } from '@mantine/core';
import { Link } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <Center py={100}>
      <Stack align="center">
        <Title>Page not found</Title>
        <Text c="dimmed">The requested Vulncat page does not exist.</Text>
        <Button component={Link} to="/">
          Return to dashboard
        </Button>
      </Stack>
    </Center>
  );
}
