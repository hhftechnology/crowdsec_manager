import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { InlineErrorBanner } from '@/components/InlineErrorBanner';
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog';

describe('Shared components', () => {
  it('calls retry action from InlineErrorBanner', () => {
    const onRetry = vi.fn();
    render(<InlineErrorBanner message="network failed" onRetry={onRetry} />);

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('calls confirm action from ConfirmActionDialog', () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmActionDialog
        open
        onOpenChange={() => {}}
        title="Delete item?"
        description="This action cannot be undone."
        confirmLabel="Delete"
        onConfirm={onConfirm}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('disables confirm button and shows loading label when loading', () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmActionDialog
        open
        onOpenChange={() => {}}
        title="Delete item?"
        description="This action cannot be undone."
        confirmLabel="Delete"
        loading
        onConfirm={onConfirm}
      />,
    );

    const workingButton = screen.getByRole('button', { name: 'Working...' });
    expect(workingButton).toBeDisabled();
  });

  it('fires onOpenChange when cancel is clicked', () => {
    const onOpenChange = vi.fn();
    render(
      <ConfirmActionDialog
        open
        onOpenChange={onOpenChange}
        title="Delete item?"
        description="This action cannot be undone."
        confirmLabel="Delete"
        onConfirm={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onOpenChange).toHaveBeenCalled();
  });
});
