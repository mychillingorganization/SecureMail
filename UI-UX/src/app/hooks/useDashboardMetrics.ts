import { useMemo } from "react";
import { useScanHistory } from "./useScanHistory";

export interface DashboardMetrics {
  totalScans: number;
  avgScanDuration: number;
  avgIssueCount: number;
  dangerousScans: number;
  lastScanTime: string | null;
}

export function useDashboardMetrics(autoFetch: boolean = false) {
  const { history, isLoading, error } = useScanHistory(500, undefined, autoFetch);

  const metrics = useMemo((): DashboardMetrics => {
    if (!history || history.length === 0) {
      return {
        totalScans: 0,
        avgScanDuration: 0,
        avgIssueCount: 0,
        dangerousScans: 0,
        lastScanTime: null,
      };
    }

    const totalScans = history.length;
    const avgScanDuration = Math.round(
      history.reduce((sum, item) => sum + item.duration_ms, 0) / totalScans
    );
    const avgIssueCount = Math.round(
      history.reduce((sum, item) => sum + item.issue_count, 0) / totalScans * 100
    ) / 100;
    const dangerousScans = history.filter((item) =>
      item.final_status.toUpperCase().includes("DANGER")
    ).length;
    const errorRate = Math.round((dangerousScans / totalScans) * 100 * 100) / 100;
    const lastScanTime = history[0]?.timestamp || null;

    return {
      totalScans,
      avgScanDuration,
      avgIssueCount,
      dangerousScans: errorRate,
      lastScanTime,
    };
  }, [history]);

  return {
    metrics,
    isLoading,
    error,
    rawHistory: history,
  };
}
