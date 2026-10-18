import { useCallback, useEffect, useRef, useState } from 'react'
import { getProjectGraph } from '@/features/projects/projectApi'
import type { ExplorerGraph, GraphRequest } from './types'
import { mergeGraph } from './graphLayout'

export function useProjectGraph(projectId: string) {
  const [graph, setGraph] = useState<ExplorerGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const controller = useRef<AbortController | null>(null)
  const lastRequest = useRef<{ params: GraphRequest; append: boolean }>({ params: {}, append: false })

  const load = useCallback(async (params: GraphRequest = {}, append = false) => {
    controller.current?.abort()
    const request = new AbortController()
    controller.current = request
    lastRequest.current = { params, append }
    setLoading(true)
    setError(null)
    if (!append) setGraph(null)
    try {
      const next = await getProjectGraph(projectId, { limit: 12, ...params }, request.signal)
      if (!request.signal.aborted && next.project_id === projectId) {
        setGraph(previous => append ? mergeGraph(previous, next) : next)
      }
    } catch (failure) {
      if (!request.signal.aborted) setError(failure instanceof Error ? failure.message : 'Could not load graph relationships.')
    } finally {
      if (!request.signal.aborted) setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    void load()
    return () => controller.current?.abort()
  }, [load])

  const retry = useCallback(() => load(lastRequest.current.params, lastRequest.current.append), [load])
  const loadMore = useCallback(() => {
    if (graph?.next_offset !== null && graph?.next_offset !== undefined) {
      return load({ ...lastRequest.current.params, offset: graph.next_offset }, true)
    }
  }, [graph?.next_offset, load])

  return { graph, loading, error, load, retry, loadMore }
}
