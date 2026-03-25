import { useEffect, useState, useCallback, useRef } from "react";
import { fetchScanHistory, type ScanHistoryItem } from "../api/scanHistory";

export function useScanHistory(
  limit: number = 50,
  scan_mode?: "rule" | "llm",
  autoFetch: boolean = false
) {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const lastFetchRef = useRef<number>(0);
  const abortControllerRef = useRef<AbortController | null>(null);

  const loadHistory = useCallback(async () => {
    // Debounce: don't fetch more than once per 5 seconds
    const now = Date.now();
    if (now - lastFetchRef.current < 5000) {
      return;
    }
    lastFetchRef.current = now;

    // Cancel previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();

    setIsLoading(true);
    try {
      const data = await fetchScanHistory(limit, scan_mode);
      setHistory(data);
      setError(null);
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        // Request was cancelled, ignore
        return;
      }
      // Don't set error state for network errors, just log them
      console.debug("Scan history fetch:", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsLoading(false);
    }
  }, [limit, scan_mode]);

  useEffect(() => {
    if (!autoFetch) return;
    
    loadHistory();
    // Poll every 30 seconds (only if autoFetch is enabled)
    const interval = setInterval(loadHistory, 30000);
    return () => {
      clearInterval(interval);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [loadHistory, autoFetch]);

  return {
    history,
    isLoading,
    error,
    refresh: loadHistory,
  };
}
