import { Alert, Button, Paper, PasswordInput, Stack, Text, TextInput, Title } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { CatMark } from '../components/CatMark';

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState('');
  const form = useForm({ initialValues: { username: '', password: '' } });

  return (
    <div className="vb-auth">
      <Paper className="vb-card vb-auth-card" p="xl" radius="lg">
        <Stack>
          <CatMark size={58} />
          <Text fw={750}>Vulncat <Text span c="dimmed" size="sm">/ Vulnerability Concatenator</Text></Text>
          <Title order={1} size="h2">
            Sign in to Vulncat
          </Title>
          <Text c="dimmed">Review service exposure using retained source evidence.</Text>
          {error ? <Alert color="red">{error}</Alert> : null}
          <form
            onSubmit={form.onSubmit(async (values) => {
              setError('');
              try {
                await login(values.username, values.password);
                const destination =
                  (location.state as { from?: { pathname?: string } } | null)?.from?.pathname ?? '/';
                navigate(destination, { replace: true });
              } catch (caught) {
                setError(caught instanceof Error ? caught.message.replace(/^\d+:\s*/, '') : 'Sign-in failed.');
              }
            })}
          >
            <Stack>
              <TextInput
                label="Username"
                autoFocus
                autoComplete="username"
                required
                {...form.getInputProps('username')}
              />
              <PasswordInput
                label="Password"
                autoComplete="current-password"
                required
                {...form.getInputProps('password')}
              />
              <Button type="submit" loading={form.submitting}>
                Sign in
              </Button>
            </Stack>
          </form>
        </Stack>
      </Paper>
    </div>
  );
}
