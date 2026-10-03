import { useState } from 'react';
import {
  Alert,
  Button,
  Group,
  Modal,
  Paper,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiRequest } from '../api/client';
import type { ManagedUser } from '../api/types';
import { EmptyState, ErrorState, LoadingState } from '../components/AsyncState';
import { PageHeader } from '../components/PageHeader';
import { formatDate, humanize } from '../utils/format';
import { useAuth } from '../auth/AuthContext';

export function UsersPage() {
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();
  const [opened, modal] = useDisclosure(false);
  const [resetUser, setResetUser] = useState<ManagedUser | null>(null);

  const users = useQuery({
    queryKey: ['users'],
    queryFn: () => apiRequest<ManagedUser[]>('/api/v1/users'),
    enabled: currentUser?.role === 'administrator',
  });

  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiRequest<ManagedUser>('/api/v1/users', { method: 'POST', body }),
    onSuccess: () => {
      modal.close();
      notifications.show({ color: 'green', message: 'User account created.' });
      void queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      apiRequest<ManagedUser>(`/api/v1/users/${id}`, { method: 'PATCH', body }),
    onSuccess: () => {
      notifications.show({ color: 'green', message: 'User account updated.' });
      void queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });

  const resetPassword = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      apiRequest(`/api/v1/users/${id}/reset-password`, {
        method: 'POST',
        body: { password },
      }),
    onSuccess: () => {
      setResetUser(null);
      notifications.show({
        color: 'green',
        message: 'Password reset. Existing sessions were signed out.',
      });
    },
  });

  if (currentUser?.role !== 'administrator') {
    return (
      <>
        <PageHeader title="Users" description="Manage local Vulncat accounts and access roles." />
        <Alert color="blue">Only administrators can manage users.</Alert>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Users"
        description="Create named administrator or read-only accounts. Avoid sharing one administrator login."
        actions={<Button onClick={modal.open}>Add user</Button>}
      />
      {users.isLoading ? (
        <LoadingState />
      ) : users.isError ? (
        <ErrorState error={users.error} />
      ) : users.data?.length ? (
        <Paper className="vb-card">
          <Table className="vb-table" striped highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>User</Table.Th>
                <Table.Th>Role</Table.Th>
                <Table.Th>Active</Table.Th>
                <Table.Th>Last login</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {users.data.map((managedUser) => (
                <Table.Tr key={managedUser.id}>
                  <Table.Td>
                    <Text fw={650}>{managedUser.display_name}</Text>
                    <Text size="xs" c="dimmed">{managedUser.username}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Select
                      value={managedUser.role}
                      data={[
                        { value: 'administrator', label: 'Administrator' },
                        { value: 'read_only', label: 'Read only' },
                      ]}
                      disabled={managedUser.id === currentUser.id}
                      onChange={(role) => {
                        if (role) update.mutate({ id: managedUser.id, body: { role } });
                      }}
                    />
                  </Table.Td>
                  <Table.Td>
                    <Switch
                      checked={managedUser.is_active}
                      disabled={managedUser.id === currentUser.id}
                      onChange={(event) =>
                        update.mutate({
                          id: managedUser.id,
                          body: { is_active: event.currentTarget.checked },
                        })
                      }
                    />
                  </Table.Td>
                  <Table.Td>{formatDate(managedUser.last_login_at, true)}</Table.Td>
                  <Table.Td>
                    <Button size="xs" variant="light" onClick={() => setResetUser(managedUser)}>
                      Reset password
                    </Button>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Paper>
      ) : (
        <EmptyState title="No users returned" message="Create the first named account." />
      )}

      <Modal opened={opened} onClose={modal.close} title="Add Vulncat user">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            create.mutate(Object.fromEntries(form.entries()));
          }}
        >
          <Stack>
            <TextInput name="username" label="Username" required />
            <TextInput name="display_name" label="Display name" required />
            <PasswordInput
              name="password"
              label="Temporary password"
              description="At least 14 characters. Share it securely."
              required
            />
            <Select
              name="role"
              label="Role"
              defaultValue="read_only"
              data={[
                { value: 'read_only', label: 'Read only' },
                { value: 'administrator', label: 'Administrator' },
              ]}
            />
            {create.error ? <ErrorState error={create.error} /> : null}
            <Group justify="flex-end">
              <Button variant="default" onClick={modal.close}>Cancel</Button>
              <Button type="submit" loading={create.isPending}>Create user</Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      <Modal
        opened={Boolean(resetUser)}
        onClose={() => setResetUser(null)}
        title={`Reset password for ${resetUser?.username ?? ''}`}
      >
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const password = String(new FormData(event.currentTarget).get('password') ?? '');
            if (resetUser) resetPassword.mutate({ id: resetUser.id, password });
          }}
        >
          <Stack>
            <Alert color="orange">
              This signs the user out everywhere. Give the new password to them through a secure channel.
            </Alert>
            <PasswordInput
              name="password"
              label={humanize('new_password')}
              description="At least 14 characters."
              required
            />
            {resetPassword.error ? <ErrorState error={resetPassword.error} /> : null}
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setResetUser(null)}>Cancel</Button>
              <Button type="submit" loading={resetPassword.isPending}>Reset password</Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </>
  );
}
