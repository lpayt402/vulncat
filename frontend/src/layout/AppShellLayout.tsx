import { useEffect, useState, type PropsWithChildren } from 'react';
import {
  AppShell,
  Avatar,
  Burger,
  Button,
  Divider,
  Group,
  NavLink,
  ScrollArea,
  Stack,
  Text,
  useComputedColorScheme,
  useMantineColorScheme,
} from '@mantine/core';
import {
  IconAdjustments,
  IconAlertTriangle,
  IconBuildingWarehouse,
  IconFileExport,
  IconHistory,
  IconLayoutDashboard,
  IconLogout,
  IconReportSearch,
  IconServer,
  IconShieldCheck,
  IconUpload,
  IconUsers,
  IconMoon,
  IconSun,
  IconTopologyStar,
} from '@tabler/icons-react';
import { NavLink as RouterNavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { CatMark } from '../components/CatMark';

const navigation = [
  { label: 'Dashboard', to: '/', icon: IconLayoutDashboard },
  { label: 'Hosts', to: '/hosts', icon: IconServer },
  { label: 'Findings', to: '/findings', icon: IconAlertTriangle },
  { label: 'Services & exposure', to: '/services', icon: IconTopologyStar },
  { label: 'Imports', to: '/imports', icon: IconUpload },
  { label: 'Identity review', to: '/identity-review', icon: IconShieldCheck },
  { label: 'Saved views', to: '/saved-views', icon: IconBuildingWarehouse },
  { label: 'Report builder', to: '/reports', icon: IconReportSearch },
  { label: 'Export history', to: '/exports', icon: IconFileExport },
  { label: 'Audit history', to: '/audit', icon: IconHistory },
  { label: 'Settings', to: '/settings', icon: IconAdjustments },
  { label: 'Users', to: '/users', icon: IconUsers, adminOnly: true },
];

export function ThemeControl() {
  const { setColorScheme } = useMantineColorScheme();
  const colorScheme = useComputedColorScheme('light');
  const dark = colorScheme === 'dark';
  return (
    <Button size="compact-sm" variant="default" className="vb-theme-control"
      leftSection={dark ? <IconSun size={16} aria-hidden="true" /> : <IconMoon size={16} aria-hidden="true" />}
      aria-label={`Switch to ${dark ? 'light' : 'dark'} theme`}
      onClick={() => setColorScheme(dark ? 'light' : 'dark')}>
      <span className="vb-theme-label">{dark ? 'Light' : 'Dark'}</span>
    </Button>
  );
}

export function AppShellLayout({ children }: PropsWithChildren) {
  const [opened, setOpened] = useState(false);
  const { pathname } = useLocation();
  const { user, logout } = useAuth();
  useEffect(() => {
    const current = navigation.find((item) => item.to === '/' ? pathname === '/' : pathname.startsWith(item.to));
    document.title = `${current?.label ?? 'Page'} · Vulncat`;
  }, [pathname]);

  return (
    <>
    <a className="vb-skip-link" href="#main-content" onClick={() => {
      setOpened(false);
      document.getElementById('main-content')?.focus();
    }}>Skip to main content</a>
    <AppShell
      className="vb-shell"
      header={{ height: 64 }}
      navbar={{ width: 248, breakpoint: 'md', collapsed: { mobile: !opened } }}
      padding={0}
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group>
            <Burger
              opened={opened}
              onClick={() => setOpened((value) => !value)}
              hiddenFrom="md"
              size="sm"
              aria-label="Toggle navigation"
              aria-expanded={opened}
              aria-controls="primary-navigation"
            />
            <Group gap="sm">
              <CatMark />
              <Stack gap={0}>
                <Text className="vb-wordmark" fw={750}>Vulncat</Text>
                <Text className="vb-compatibility" size="xs" c="dimmed">Vulnerability Concatenator</Text>
              </Stack>
            </Group>
          </Group>
          <Group gap="sm">
            <ThemeControl />
            <Avatar size="sm" color="indigo">
              {user?.display_name?.slice(0, 1).toUpperCase()}
            </Avatar>
            <Stack gap={0} visibleFrom="sm">
              <Text size="sm" fw={600}>
                {user?.display_name}
              </Text>
              <Text size="xs" c="dimmed">
                {user?.role.replaceAll('_', ' ')}
              </Text>
            </Stack>
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar className="vb-navbar" p="md" id="primary-navigation" aria-label="Primary navigation">
        <Stack mb="lg" gap={4}>
          <Text className="vb-brand" size="sm" fw={650}>Vulnerability Concatenator</Text>
          <Text size="xs" className="vb-nav-caption">Source records and reviewed mappings</Text>
        </Stack>
        <AppShell.Section grow component={ScrollArea}>
          {navigation.filter((item) => !item.adminOnly || user?.role === 'administrator').map((item) => (
            <NavLink
              className="vb-nav-link"
              component={RouterNavLink}
              to={item.to}
              key={item.to}
              label={item.label}
              leftSection={<item.icon size={18} />}
              active={item.to === '/' ? pathname === '/' : pathname.startsWith(item.to)}
              onClick={() => setOpened(false)}
            />
          ))}
        </AppShell.Section>
        <Divider color="rgba(255,255,255,.12)" my="md" />
        <Text size="xs" className="vb-nav-caption" mb="sm">Offline files · local workspace</Text>
        <Button
          color="gray"
          variant="subtle"
          fullWidth
          leftSection={<IconLogout size={18} />}
          onClick={() => void logout()}
          styles={{ root: { color: '#cbd5e1' } }}
        >
          Sign out
        </Button>
      </AppShell.Navbar>
      <AppShell.Main className="vb-main" component="div">
        <main className="vb-page" id="main-content" tabIndex={-1}>{children}</main>
      </AppShell.Main>
    </AppShell>
    </>
  );
}
