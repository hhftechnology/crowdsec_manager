import { useState, useEffect, useRef, useCallback } from 'react'

interface UseInfiniteScrollOptions<T> {
  /** Full data array to paginate */
  data: T[]
  /** Items per page (default 50) */
  pageSize?: number
}

interface UseInfiniteScrollResult<T> {
  /** Currently visible items */
  items: T[]
  /** Whether more items can be loaded */
  hasMore: boolean
  /** Ref to attach to the sentinel element */
  sentinelRef: React.RefObject<HTMLDivElement | null>
  /** Reset back to first page */
  reset: () => void
}

/**
 * Client-side infinite scroll using IntersectionObserver.
 * Attach `sentinelRef` to a div at the bottom of your list.
 */
export function useInfiniteScroll<T>({
  data,
  pageSize = 50,
}: UseInfiniteScrollOptions<T>): UseInfiniteScrollResult<T> {
  const [visibleCount, setVisibleCount] = useState(pageSize)
  const sentinelRef = useRef<HTMLDivElement | null>(null)

  const hasMore = visibleCount < data.length
  const items = data.slice(0, visibleCount)

  // Reset when data changes (e.g. new filters)
  useEffect(() => {
    setVisibleCount(pageSize)
  }, [data, pageSize])

  useEffect(() => {
    const el = sentinelRef.current
    if (!el || !hasMore) return

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) {
          setVisibleCount(prev => Math.min(prev + pageSize, data.length))
        }
      },
      { threshold: 0.1 },
    )

    observer.observe(el)
    return () => observer.disconnect()
  }, [hasMore, pageSize, data.length])

  const reset = useCallback(() => {
    setVisibleCount(pageSize)
  }, [pageSize])

  return { items, hasMore, sentinelRef, reset }
}
