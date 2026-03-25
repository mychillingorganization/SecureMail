/**
 * API utilities for scan history operations via PostgreSQL backend
 */

export type ScanHistoryItem = {
  id: string;
  timestamp: string;
  scan_mode: "rule" | "llm";
  file_name: string;
  sender: string | null;
  receiver: string | null;
  final_status: string;
  issue_count: number;
  duration_ms: number;
  termination_reason: string | null;
  ai_classify: string | null;
  ai_reason: string | null;
  ai_summary: string | null;
  ai_provider: string | null;
  ai_confidence_percent: number | null;
  execution_logs: string[];
  ai_cot_steps: string[];
};

export type PaginatedScanHistoryResponse = {
  total: number;
  skip: number;
  limit: number;
  passed_count: number;
  issues_count: number;
  danger_count: number;
  items: ScanHistoryItem[];
};

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";

/**
 * Save a scan result to PostgreSQL
 */
export async function saveScanToHistory(data: {
  scan_mode: "rule" | "llm";
  file_name: string;
  sender: string | null;
  receiver: string | null;
  final_status: string;
  issue_count: number;
  duration_ms: number;
  termination_reason: string | null;
  ai_classify: string | null;
  ai_reason: string | null;
  ai_summary: string | null;
  ai_provider: string | null;
  ai_confidence_percent: number | null;
  execution_logs: string[];
  ai_cot_steps: string[];
}): Promise<ScanHistoryItem> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(`${API_BASE_URL}/api/v1/scan-history`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn(`API error ${response.status} saving scan history`);
      throw new Error(`HTTP ${response.status}`);
    }

    return response.json();
  } catch (err) {
    // Log but don't throw - allow scan results to display even if history save fails
    console.debug("Scan history save failed (non-blocking):", err instanceof Error ? err.message : "Unknown error");
    throw err;
  }
}

/**
 * Fetch scan history from PostgreSQL
 */
export async function fetchScanHistory(
  limit: number = 10,
  skip: number = 0,
  search: string = "",
  scan_mode?: "rule" | "llm"
): Promise<PaginatedScanHistoryResponse> {
  try {
    const params = new URLSearchParams();
    params.append("limit", limit.toString());
    params.append("skip", skip.toString());
    if (search.trim()) {
      params.append("search", search.trim());
    }
    if (scan_mode) {
      params.append("scan_mode", scan_mode);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(
      `${API_BASE_URL}/api/v1/scan-history?${params.toString()}`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
        signal: controller.signal,
      }
    );

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn(`API error ${response.status} fetching scan history`);
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    return {
      total: typeof data?.total === "number" ? data.total : 0,
      skip: typeof data?.skip === "number" ? data.skip : 0,
      limit: typeof data?.limit === "number" ? data.limit : limit,
      passed_count: typeof data?.passed_count === "number" ? data.passed_count : 0,
      issues_count: typeof data?.issues_count === "number" ? data.issues_count : 0,
      danger_count: typeof data?.danger_count === "number" ? data.danger_count : 0,
      items: Array.isArray(data?.items) ? data.items : [],
    };
  } catch (err) {
    console.debug("Scan history fetch failed:", err instanceof Error ? err.message : "Unknown error");
    throw err;
  }
}
