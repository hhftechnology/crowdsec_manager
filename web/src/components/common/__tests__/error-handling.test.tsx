import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ErrorBoundary, DefaultErrorFallback } from '../ErrorBoundary'
import { ErrorState, NetworkErrorState, DataErrorState } from '../ErrorStates'
import { LoadingState, LoadingSpinner } from '../LoadingStates'

// Mock component that throws an error
const ThrowError = ({ shouldThrow }: { shouldThrow: boolean }) => {
  if (shouldThrow) {
    throw new Error('Test error')
  }
  return <div>No error</div>
}

describe('Error Handling Components', () => {
  describe('ErrorBoundary', () => {
    it('should render children when no error occurs', () => {
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={false} />
        </ErrorBoundary>
      )
      
      expect(screen.getByText('No error')).toBeInTheDocument()
    })

    it('should render error fallback when error occurs', () => {
      // Suppress console.error for this test
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      
      render(
        <ErrorBoundary>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      )
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
      expect(screen.getByText('Try Again')).toBeInTheDocument()
      
      consoleSpy.mockRestore()
    })

    it('should call onError callback when error occurs', () => {
      const onError = vi.fn()
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
      
      render(
        <ErrorBoundary onError={onError}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      )
      
      expect(onError).toHaveBeenCalledWith(
        expect.any(Error),
        expect.any(Object)
      )
      
      consoleSpy.mockRestore()
    })
  })

  describe('ErrorState', () => {
    it('should render error message and retry button', () => {
      const onRetry = vi.fn()
      
      render(
        <ErrorState
          error={new Error('Test error message')}
          onRetry={onRetry}
        />
      )
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
      expect(screen.getByText('Test error message')).toBeInTheDocument()
      expect(screen.getByText('Try Again')).toBeInTheDocument()
      
      fireEvent.click(screen.getByText('Try Again'))
      expect(onRetry).toHaveBeenCalled()
    })

    it('should render different error types correctly', () => {
      render(
        <NetworkErrorState
          error="Network connection failed"
          onRetry={() => {}}
        />
      )
      
      expect(screen.getByText('Connection Error')).toBeInTheDocument()
      expect(screen.getByText('Network connection failed')).toBeInTheDocument()
    })

    it('should render inline variant correctly', () => {
      render(
        <ErrorState
          variant="inline"
          error="Inline error"
          onRetry={() => {}}
        />
      )
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
      // The component actually shows "Try Again" not "Retry"
      expect(screen.getByText('Try Again')).toBeInTheDocument()
    })
  })

  describe('DataErrorState', () => {
    it('should render loading state', () => {
      render(
        <DataErrorState
          isLoading={true}
          isEmpty={false}
        />
      )
      
      expect(screen.getByText('Loading...')).toBeInTheDocument()
    })

    it('should render empty state', () => {
      render(
        <DataErrorState
          isLoading={false}
          isEmpty={true}
          emptyMessage="No data found"
        />
      )
      
      expect(screen.getByText('No data found')).toBeInTheDocument()
    })

    it('should render error state', () => {
      render(
        <DataErrorState
          isLoading={false}
          isEmpty={false}
          error="Data loading failed"
        />
      )
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    })
  })

  describe('LoadingState', () => {
    it('should render loading spinner when loading', () => {
      render(
        <LoadingState loading={true} error={null} onRetry={() => {}}>
          <div>Content</div>
        </LoadingState>
      )
      
      expect(screen.getByText('Loading...')).toBeInTheDocument()
      expect(screen.queryByText('Content')).not.toBeInTheDocument()
    })

    it('should render error state when error exists', () => {
      const onRetry = vi.fn()
      
      render(
        <LoadingState 
          loading={false} 
          error="Loading failed" 
          onRetry={onRetry}
        >
          <div>Content</div>
        </LoadingState>
      )
      
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
      expect(screen.getByText('Loading failed')).toBeInTheDocument()
      expect(screen.getByText('Try Again')).toBeInTheDocument()
      
      fireEvent.click(screen.getByText('Try Again'))
      expect(onRetry).toHaveBeenCalled()
    })

    it('should render children when no loading or error', () => {
      render(
        <LoadingState loading={false} error={null} onRetry={() => {}}>
          <div>Content</div>
        </LoadingState>
      )
      
      expect(screen.getByText('Content')).toBeInTheDocument()
    })
  })

  describe('LoadingSpinner', () => {
    it('should render with different sizes', () => {
      const { rerender } = render(<LoadingSpinner size="sm" />)
      expect(document.querySelector('.h-4')).toBeInTheDocument()
      
      rerender(<LoadingSpinner size="md" />)
      expect(document.querySelector('.h-6')).toBeInTheDocument()
      
      rerender(<LoadingSpinner size="lg" />)
      expect(document.querySelector('.h-8')).toBeInTheDocument()
    })
  })
})