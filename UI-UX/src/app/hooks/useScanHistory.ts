import { useEffect, useState, useCallback, useRef } from "react";
import { fetchScanHistory, type ScanHistoryItem } from "../api/scanHistory";

export function useScanHistory(
  limit: number = 10,
  searchTerm: string = "",
  scan_mode?: "rule" | "llm",
  autoFetch: boolean = false
) {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [passedCount, setPassedCount] = useState(0);
  const [issuesCount, setIssuesCount] = useState(0);
  const [dangerCount, setDangerCount] = useState(0);
  const abortControllerRef = useRef<AbortController | null>(null);

  const totalPages = Math.max(1, Math.ceil(totalItems / limit));

  const loadHistory = useCallback(async () => {
    // Cancel previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();

    setIsLoading(true);
    try {
      const skip = (currentPage - 1) * limit;
      const data = await fetchScanHistory(limit, skip, searchTerm, scan_mode);
      setHistory(data.items);
      setTotalItems(data.total);
      setPassedCount(data.passed_count || 0);
      setIssuesCount(data.issues_count || 0);
      setDangerCount(data.danger_count || 0);
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
  }, [limit, scan_mode, currentPage, searchTerm]);

  useEffect(() => {
    setCurrentPage(1);
  }, [scan_mode, limit, searchTerm]);

  useEffect(() => {
    // Always load history on mount
    loadHistory();
    
    // If autoFetch is enabled, also set up polling
    if (!autoFetch) return;
    
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
    currentPage,
    totalItems,
    totalPages,
    passedCount,
    issuesCount,
    dangerCount,
    setCurrentPage,
    refresh: loadHistory,
  };
}
