import { MantineProvider } from '@mantine/core';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EmptyState, ErrorState } from './AsyncState';

describe('operational empty and error states', () => {
  it('renders a clear empty inventory message', () => {
    render(
      <MantineProvider>
        <EmptyState title="No hosts" message="Upload a scan to populate the inventory." />
      </MantineProvider>,
    );
    expect(screen.getByText('No hosts')).toBeVisible();
    expect(screen.getByText(/Upload a scan/)).toBeVisible();
  });

  it('does not expose status-code noise in a user-facing error', () => {
    render(
      <MantineProvider>
        <ErrorState error={new Error('500: An internal error occurred.')} />
      </MantineProvider>,
    );
    expect(screen.getByText('An internal error occurred.')).toBeVisible();
    expect(screen.queryByText(/^500:/)).not.toBeInTheDocument();
  });
});
