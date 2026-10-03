import { Alert, Button, Paper, PasswordInput, Stack, Text, TextInput, Title } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconInfoCircle } from '@tabler/icons-react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { CatMark } from '../components/CatMark';

export function SetupPage() {
  const { setup } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  const form = useForm({
    initialValues: { username: '', displayName: '', password: '', confirmPassword: '' },
    validate: {
      username: (value) => (/^[a-z0-9._-]{3,64}$/.test(value) ? null : 'Use 3-64 lowercase letters, numbers, dots, underscores, or hyphens.'),
      displayName: (value) => (value.trim() ? null : 'Display name is required.'),
      password: (value) => (value.length >= 14 ? null : 'Use at least 14 characters.'),
      confirmPassword: (value, values) => (value === values.password ? null : 'Passwords must match.'),
    },
  });

  return (
    <div className="vb-auth">
      <Paper className="vb-card vb-auth-card" p="xl" radius="lg">
        <Stack>
          <CatMark size={58} />
          <Text fw={750}>Vulncat <Text span c="dimmed" size="sm">/ Vulnerability Concatenator</Text></Text>
          <Title order={1} size="h2">
            Set up Vulncat
          </Title>
          <Text c="dimmed">
            Create the initial Vulncat administrator. No default account or password is installed.
          </Text>
          <Alert icon={<IconInfoCircle size={18} />} color="blue">
            Use a unique password. This account can import scan evidence, resolve identity conflicts, and generate reports.
          </Alert>
          {error ? <Alert color="red">{error}</Alert> : null}
          <form
            onSubmit={form.onSubmit(async (values) => {
              setError('');
              try {
                await setup(values.username, values.displayName, values.password);
                navigate('/', { replace: true });
              } catch (caught) {
                setError(caught instanceof Error ? caught.message.replace(/^\d+:\s*/, '') : 'Setup failed.');
              }
            })}
          >
            <Stack>
              <TextInput label="Username" autoComplete="username" required {...form.getInputProps('username')} />
              <TextInput label="Display name" autoComplete="name" required {...form.getInputProps('displayName')} />
              <PasswordInput label="Password" autoComplete="new-password" required {...form.getInputProps('password')} />
              <PasswordInput
                label="Confirm password"
                autoComplete="new-password"
                required
                {...form.getInputProps('confirmPassword')}
              />
              <Button type="submit" loading={form.submitting}>
                Create administrator
              </Button>
            </Stack>
          </form>
        </Stack>
      </Paper>
    </div>
  );
}
