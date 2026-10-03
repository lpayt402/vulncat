import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MantineProvider, localStorageColorSchemeManager } from '@mantine/core';
import { MemoryRouter } from 'react-router-dom';
import { AppShellLayout, ThemeControl } from './AppShellLayout';

vi.mock('../auth/AuthContext', () => ({ useAuth: () => ({ user: { role: 'read_only', display_name: 'Reader' }, logout: vi.fn() }) }));
afterEach(() => { cleanup(); localStorage.clear(); });

describe('workbench shell', () => {
  it('switches themes by keyboard, persists the choice, and restores it on remount', async () => {
    const user = userEvent.setup();
    const renderControl = () => render(<MantineProvider defaultColorScheme="light" colorSchemeManager={localStorageColorSchemeManager({ key: 'vulncat-color-scheme' })}><ThemeControl /></MantineProvider>);
    const first = renderControl();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Switch to dark theme' })).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('button', { name: 'Switch to light theme' })).toBeInTheDocument();
    expect(localStorage.getItem('vulncat-color-scheme')).toBe('dark');
    first.unmount();
    renderControl();
    expect(screen.getByRole('button', { name: 'Switch to light theme' })).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute('data-mantine-color-scheme', 'dark');
  });

  it('preserves legacy links, adds exposure, and gives the skip link a real focus target', async () => {
    render(<MantineProvider><MemoryRouter initialEntries={['/services']}><AppShellLayout><h1>Service exposure</h1></AppShellLayout></MemoryRouter></MantineProvider>);
    const user = userEvent.setup();
    await user.tab();
    expect(screen.getByRole('link', { name: 'Skip to main content' })).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('main')).toHaveFocus();
    expect(screen.getByRole('link', { name: 'Services & exposure' })).toHaveAttribute('href', '/services');
    expect(screen.getByRole('link', { name: 'Identity review' })).toHaveAttribute('href', '/identity-review');
    expect(screen.getByRole('link', { name: 'Report builder' })).toHaveAttribute('href', '/reports');
    expect(screen.getAllByText('Vulnerability Concatenator')[0]).toBeInTheDocument();
    expect(document.querySelector('.vb-cat-mark')).toHaveAttribute('alt', '');
    expect(document.title).toBe('Services & exposure · Vulncat');
  });
});
