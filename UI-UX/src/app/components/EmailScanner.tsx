import { useMemo, useRef, useState, type DragEvent } from "react";
import { Upload, FileText, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";

import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { useTheme } from "./ThemeContext";
import { Button } from "./ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { cn } from "./ui/utils";
import { saveScanToHistory } from "../api/scanHistory";

type ScanMode = "rule" | "llm";

type ScanResponse = {
  final_status: string;
  issue_count: number;
  termination_reason: string | null;
  execution_logs: string[];
  ai_classify?: string | null;
  ai_reason?: string | null;
  ai_summary?: string | null;
  ai_provider?: string | null;
  ai_confidence_percent?: number | null;
  ai_cot_steps?: string[];
};

type ScanBatchItemResult = {
  index: number;
  email_path: string;
  success: boolean;
  result?: ScanResponse | null;
  error?: string | null;
};

type ScanBatchResponse = {
  total: number;
  succeeded: number;
  failed: number;
  items: ScanBatchItemResult[];
};

async function extractSenderReceiver(file: File): Promise<{ sender: string | null; receiver: string | null }> {
  try {
    const raw = await file.text();
    const senderMatch = raw.match(/^From:\s*(.+)$/im);
    const receiverMatch = raw.match(/^To:\s*(.+)$/im);
    return {
      sender: senderMatch?.[1]?.trim() || null,
      receiver: receiverMatch?.[1]?.trim() || null,
    };
  } catch {
    return { sender: null, receiver: null };
  }
}

const API_BASE_URL =
  (import.meta as { env?: Record<string, string | undefined> }).env?.VITE_API_BASE_URL || "http://localhost:8080";

function isValidEml(file: File | null): file is File {
  return Boolean(file && file.name.toLowerCase().endsWith(".eml"));
}

function isValidEmlCandidate(file: File): boolean {
  return file.name.toLowerCase().endsWith(".eml");
}

function statusTone(status: string) {
  const normalized = status.toUpperCase();
  if (normalized.includes("DANGER")) return "danger";
  if (normalized.includes("SUSPICIOUS") || normalized.includes("WARNING")) return "warning";
  if (normalized.includes("PASS") || normalized.includes("SAFE")) return "safe";
  return "unknown";
}

export function EmailScanner() {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [scanMode, setScanMode] = useState<ScanMode>("rule");
  const [files, setFiles] = useState<File[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [userAcceptsDanger, setUserAcceptsDanger] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [batchResult, setBatchResult] = useState<ScanBatchResponse | null>(null);
  const [selectedBatchIndex, setSelectedBatchIndex] = useState<number | null>(null);

  const selectedBatchItem = useMemo(() => {
    if (!batchResult || batchResult.items.length === 0) return null;
    if (selectedBatchIndex !== null) {
      return batchResult.items.find((item) => item.index === selectedBatchIndex) ?? null;
    }
    return batchResult.items.find((item) => item.success && item.result) ?? batchResult.items[0];
  }, [batchResult, selectedBatchIndex]);

  const activeResult = useMemo(() => {
    if (selectedBatchItem?.success && selectedBatchItem.result) {
      return selectedBatchItem.result;
    }
    return batchResult ? null : result;
  }, [batchResult, result, selectedBatchItem]);

  const status = useMemo(() => {
    if (!activeResult) return null;
    return statusTone(activeResult.final_status);
  }, [activeResult]);

  const visibleLogs = useMemo(() => {
    if (!activeResult?.execution_logs?.length) return [];
    const normalized = activeResult.execution_logs
      .flatMap((line) => line.split(/\r?\n/))
      .map((line) => line.trimEnd())
      .filter((line) => line.trim().length > 0);
    // Avoid rendering very large log payloads in one paint.
    return normalized.slice(0, 120);
  }, [activeResult]);

  const totalDisplayLogs = useMemo(() => {
    if (!activeResult?.execution_logs?.length) return 0;
    return activeResult.execution_logs
      .flatMap((line) => line.split(/\r?\n/))
      .filter((line) => line.trim().length > 0).length;
  }, [activeResult]);

  const selectFiles = (candidates: FileList | File[] | null) => {
    if (!candidates) {
      return;
    }

    const selected = Array.from(candidates);
    if (selected.length === 0) {
      return;
    }

    const invalid = selected.filter((item) => !isValidEmlCandidate(item)).map((item) => item.name);
    if (invalid.length > 0) {
      setError(`Only .eml files are supported. Invalid: ${invalid.slice(0, 3).join(", ")}`);
      return;
    }

    setError(null);
    setFiles(selected);
    setBatchResult(null);
    setSelectedBatchIndex(null);
  };



  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setDragActive(false);
    selectFiles(event.dataTransfer.files ?? null);
  };

  const handleUpload = async () => {
    if (files.length === 0) {
      setError("Select at least one valid .eml file before scanning.");
      return;
    }

    setError(null);
    setIsUploading(true);
    setResult(null);
    setBatchResult(null);
    setSelectedBatchIndex(null);
    const uploadStartTime = Date.now();

    try {
      const controller = new AbortController();
      // 5 minute timeout for large file uploads
      const timeoutId = setTimeout(() => controller.abort(), 300000);

      if (files.length === 1 && isValidEml(files[0])) {
        const endpoint = scanMode === "llm" ? "/api/v1/scan-upload-llm" : "/api/v1/scan-upload";
        const formData = new FormData();
        formData.append("file", files[0]);
        formData.append("user_accepts_danger", String(userAcceptsDanger));

        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
          method: "POST",
          body: formData,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          let detail = "Scan request failed.";
          try {
            const payload = await response.json();
            detail = payload?.detail ?? detail;
          } catch {
            // Non-JSON error payload.
          }
          throw new Error(typeof detail === "string" ? detail : "Scan request failed.");
        }

        const payload = (await response.json()) as ScanResponse;
        const durationMs = Date.now() - uploadStartTime;
        setResult(payload);
        const participants = await extractSenderReceiver(files[0]);

        // Save to PostgreSQL history truly non-blocking.
        void saveScanToHistory({
          scan_mode: scanMode,
          file_name: files[0].name,
          sender: participants.sender,
          receiver: participants.receiver,
          final_status: payload.final_status,
          issue_count: payload.issue_count,
          duration_ms: durationMs,
          termination_reason: payload.termination_reason ?? null,
          ai_classify: payload.ai_classify ?? null,
          ai_reason: payload.ai_reason ?? null,
          ai_summary: payload.ai_summary ?? null,
          ai_provider: payload.ai_provider ?? null,
          ai_confidence_percent: payload.ai_confidence_percent ?? null,
          execution_logs: payload.execution_logs,
          ai_cot_steps: payload.ai_cot_steps ?? [],
        }).catch((historyError) => {
          console.debug("Scan history save failed (non-blocking):", historyError);
        });
      } else {
        const endpoint = scanMode === "llm" ? "/api/v1/scan-upload-llm-batch" : "/api/v1/scan-upload-batch";
        const formData = new FormData();
        files.forEach((candidate) => {
          formData.append("files", candidate);
        });
        formData.append("user_accepts_danger", String(userAcceptsDanger));
        formData.append("continue_on_error", "true");

        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
          method: "POST",
          body: formData,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          let detail = "Batch scan request failed.";
          try {
            const payload = await response.json();
            detail = payload?.detail ?? detail;
          } catch {
            // Non-JSON error payload.
          }
          throw new Error(typeof detail === "string" ? detail : "Batch scan request failed.");
        }

        const payload = (await response.json()) as ScanBatchResponse;
        const durationMs = Date.now() - uploadStartTime;
        const durationPerItem = Math.max(1, Math.round(durationMs / Math.max(payload.items.length, 1)));

        setBatchResult(payload);
        const firstSuccessful = payload.items.find((item) => item.success && item.result);
        setSelectedBatchIndex(firstSuccessful?.index ?? (payload.items[0]?.index ?? null));

        for (const item of payload.items) {
          if (!item.success || !item.result) continue;
          const sourceFile = files[item.index] ?? null;
          const participants = sourceFile ? await extractSenderReceiver(sourceFile) : { sender: null, receiver: null };
          const fallbackName = sourceFile?.name ?? item.email_path;

          void saveScanToHistory({
            scan_mode: scanMode,
            file_name: fallbackName,
            sender: participants.sender,
            receiver: participants.receiver,
            final_status: item.result.final_status,
            issue_count: item.result.issue_count,
            duration_ms: durationPerItem,
            termination_reason: item.result.termination_reason ?? null,
            ai_classify: item.result.ai_classify ?? null,
            ai_reason: item.result.ai_reason ?? null,
            ai_summary: item.result.ai_summary ?? null,
            ai_provider: item.result.ai_provider ?? null,
            ai_confidence_percent: item.result.ai_confidence_percent ?? null,
            execution_logs: item.result.execution_logs,
            ai_cot_steps: item.result.ai_cot_steps ?? [],
          }).catch((historyError) => {
            console.debug("Batch scan history save failed (non-blocking):", historyError);
          });
        }
      }
    } catch (uploadError) {
      let message = "Unexpected upload error.";
      
      if (uploadError instanceof Error) {
        message = uploadError.message;
        if (uploadError.name === "AbortError") {
          message = "Request timeout - file may be too large or network is slow. Please try again.";
        }
      }
      
      console.error("Upload error:", uploadError);
      setError(message);
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className={cn("relative flex h-screen w-full overflow-hidden transition-colors", isDark ? "bg-[#030308] text-white" : "bg-slate-50 text-slate-900")}>
      <div className={cn("absolute inset-0", isDark ? "bg-gradient-to-br from-[#0a0a1a] via-[#05050f] to-black opacity-90" : "bg-gradient-to-br from-slate-100 via-white to-slate-50 opacity-90")} />

      <Sidebar />

      <div className="relative z-10 flex flex-1 flex-col overflow-hidden">
        <Header />

        <main className="flex-1 overflow-auto p-6 md:p-8">
          <div className="mx-auto grid max-w-7xl gap-6 lg:grid-cols-[1.15fr_1fr]">
            <Card className={cn("border", isDark ? "border-white/10 bg-black/30 backdrop-blur-xl" : "border-slate-200 bg-white/80") }>
              <CardHeader>
                <CardTitle className="text-xl">Email Scanner</CardTitle>
                <CardDescription>
                  Upload a real .eml file for rule-based or LLM deep-dive analysis.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="flex gap-2">
                  <Button
                    variant={scanMode === "rule" ? "default" : "outline"}
                    onClick={() => setScanMode("rule")}
                    type="button"
                    className="flex-1"
                  >
                    Rule-Based
                  </Button>
                  <Button
                    variant={scanMode === "llm" ? "default" : "outline"}
                    onClick={() => setScanMode("llm")}
                    type="button"
                    className="flex-1"
                  >
                    LLM Deep Dive
                  </Button>
                </div>

                <div
                  className={cn(
                    "rounded-xl border-2 border-dashed p-8 text-center transition-all",
                    dragActive
                      ? isDark
                        ? "border-blue-400 bg-blue-500/10"
                        : "border-blue-500 bg-blue-50"
                      : isDark
                        ? "border-white/20 bg-white/5"
                        : "border-slate-300 bg-slate-50",
                  )}
                  onDragEnter={(event) => {
                    event.preventDefault();
                    setDragActive(true);
                  }}
                  onDragOver={(event) => {
                    event.preventDefault();
                    setDragActive(true);
                  }}
                  onDragLeave={(event) => {
                    event.preventDefault();
                    setDragActive(false);
                  }}
                  onDrop={handleDrop}
                >
                  <Upload className={cn("mx-auto mb-3 h-8 w-8", isDark ? "text-blue-300" : "text-blue-600")} />
                  <p className="text-sm font-medium">Drag and drop your .eml file(s) here</p>
                  <p className={cn("mt-1 text-xs", isDark ? "text-white/50" : "text-slate-500")}>or browse from your computer</p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".eml"
                    multiple
                    className="hidden"
                    onChange={(event) => selectFiles(event.target.files ?? null)}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    className="mt-4"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    Browse Files
                  </Button>
                </div>

                <label className="flex items-center gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={userAcceptsDanger}
                    onChange={(event) => setUserAcceptsDanger(event.target.checked)}
                  />
                  Continue scan even if dangerous indicators are found.
                </label>

                {files.length > 0 ? (
                  <div className={cn("flex items-center justify-between rounded-lg border px-4 py-3", isDark ? "border-white/15 bg-white/5" : "border-slate-200 bg-white") }>
                    <div className="flex items-center gap-2 text-sm">
                      <FileText className="h-4 w-4" />
                      <span className="max-w-[320px] truncate">
                        {files.length === 1 ? files[0].name : `${files.length} files selected`}
                      </span>
                    </div>
                    <span className={cn("text-xs", isDark ? "text-white/50" : "text-slate-500")}>
                      {(files.reduce((sum, item) => sum + item.size, 0) / 1024).toFixed(1)} KB
                    </span>
                  </div>
                ) : null}

                {files.length > 1 ? (
                  <div className={cn("rounded-lg border px-4 py-3 text-xs", isDark ? "border-white/10 bg-white/5 text-white/70" : "border-slate-200 bg-slate-50 text-slate-600") }>
                    {files.slice(0, 5).map((entry) => (
                      <p key={`${entry.name}-${entry.size}`} className="truncate">{entry.name}</p>
                    ))}
                    {files.length > 5 ? <p className="mt-1">+ {files.length - 5} more</p> : null}
                  </div>
                ) : null}

                {error ? (
                  <div className={cn("rounded-md border px-3 py-2 text-sm", isDark ? "border-red-400/30 bg-red-500/10 text-red-200" : "border-red-200 bg-red-50 text-red-700")}>{error}</div>
                ) : null}

                <Button type="button" className="w-full" disabled={isUploading} onClick={handleUpload}>
                  {isUploading ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    files.length > 1 ? `Scan ${files.length} Emails` : "Scan Email"
                  )}
                </Button>
              </CardContent>
            </Card>

            <Card className={cn("border", isDark ? "border-white/10 bg-black/30 backdrop-blur-xl" : "border-slate-200 bg-white/80") }>
              <CardHeader>
                <CardTitle className="text-xl">Scan Result</CardTitle>
                <CardDescription>
                  Real-time response from the orchestrator API.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {!activeResult && !batchResult ? (
                  <div className={cn("rounded-lg border border-dashed p-6 text-sm", isDark ? "border-white/15 text-white/60" : "border-slate-300 text-slate-500") }>
                    Upload an email and run scan to see real backend results.
                  </div>
                ) : (
                  <>
                    {batchResult ? (
                      <div className={cn("space-y-3 rounded-lg border p-3", isDark ? "border-white/10 bg-white/5" : "border-slate-200 bg-slate-50") }>
                        <p className="text-xs font-semibold uppercase tracking-wide">Batch Summary</p>
                        <p className={cn("text-xs", isDark ? "text-white/70" : "text-slate-600")}>
                          Total: {batchResult.total} | Succeeded: {batchResult.succeeded} | Failed: {batchResult.failed}
                        </p>
                        <div className="max-h-32 space-y-1 overflow-auto">
                          {batchResult.items.map((item) => {
                            const sourceName = files[item.index]?.name ?? item.email_path;
                            const itemFinalStatus = item.result?.final_status ?? null;
                            const itemTone = itemFinalStatus ? statusTone(itemFinalStatus) : null;
                            const itemLabel = item.success
                              ? (itemFinalStatus ?? "COMPLETED")
                              : "ERROR";
                            const itemLabelClass = !item.success
                              ? "text-rose-500"
                              : itemTone === "danger"
                                ? "text-rose-500"
                                : itemTone === "warning"
                                  ? "text-amber-500"
                                  : itemTone === "safe"
                                    ? "text-emerald-500"
                                    : "text-slate-500";
                            return (
                              <button
                                key={`${item.index}-${sourceName}`}
                                type="button"
                                className={cn(
                                  "flex w-full items-center justify-between rounded border px-2 py-1 text-left text-xs",
                                  selectedBatchItem?.index === item.index
                                    ? isDark
                                      ? "border-blue-300/40 bg-blue-500/20"
                                      : "border-blue-300 bg-blue-100"
                                    : isDark
                                      ? "border-white/10 bg-black/20"
                                      : "border-slate-200 bg-white",
                                )}
                                onClick={() => setSelectedBatchIndex(item.index)}
                              >
                                <span className="truncate pr-2">{sourceName}</span>
                                <span className={cn(itemLabelClass)}>{itemLabel}</span>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ) : null}

                    {selectedBatchItem && !selectedBatchItem.success ? (
                      <div className={cn("rounded-md border px-3 py-2 text-sm", isDark ? "border-red-400/30 bg-red-500/10 text-red-200" : "border-red-200 bg-red-50 text-red-700") }>
                        {selectedBatchItem.error ?? "Batch item failed."}
                      </div>
                    ) : null}

                    {activeResult ? (
                      <>
                    <div className="flex items-center gap-2">
                      {status === "safe" ? <ShieldCheck className="h-5 w-5 text-emerald-500" /> : null}
                      {status === "warning" ? <ShieldQuestion className="h-5 w-5 text-amber-500" /> : null}
                      {status === "danger" ? <ShieldAlert className="h-5 w-5 text-red-500" /> : null}
                      <Badge variant={status === "danger" ? "destructive" : "default"}>{activeResult.final_status}</Badge>
                      <span className={cn("text-xs", isDark ? "text-white/60" : "text-slate-500")}>Issues: {activeResult.issue_count}</span>
                    </div>

                    {activeResult.termination_reason ? (
                      <div className={cn("rounded-md border px-3 py-2 text-sm", isDark ? "border-amber-400/30 bg-amber-500/10 text-amber-100" : "border-amber-200 bg-amber-50 text-amber-800") }>
                        {activeResult.termination_reason}
                      </div>
                    ) : null}

                    {(activeResult.ai_reason || activeResult.ai_summary || activeResult.ai_classify) ? (
                      <div className={cn("space-y-3 rounded-lg border p-4", isDark ? "border-blue-400/20 bg-blue-500/10" : "border-blue-200 bg-blue-50") }>
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-semibold">🤖 LLM Analysis</span>
                          <span className={cn("text-xs", isDark ? "text-blue-200" : "text-blue-700") }>
                            {activeResult.ai_provider ?? "AI"}
                            {typeof activeResult.ai_confidence_percent === "number" ? ` - ${activeResult.ai_confidence_percent}%` : ""}
                          </span>
                        </div>
                        
                        {activeResult.ai_classify ? (
                          <div>
                            <p className={cn("text-xs font-medium mb-1", isDark ? "text-white/60" : "text-slate-600")}>Classification</p>
                            <p className={cn("text-sm font-bold capitalize", activeResult.ai_classify === "safe" ? (isDark ? "text-emerald-300" : "text-emerald-700") : (isDark ? "text-rose-300" : "text-rose-700"))}>
                              {activeResult.ai_classify}
                            </p>
                          </div>
                        ) : null}
                        
                        {activeResult.ai_reason ? (
                          <div>
                            <p className={cn("text-xs font-medium mb-1", isDark ? "text-white/60" : "text-slate-600")}>Reason</p>
                            <p className="text-sm leading-relaxed">{activeResult.ai_reason}</p>
                          </div>
                        ) : null}
                      </div>
                    ) : null}

                    <div>
                      <div className={cn("mb-2 text-xs font-semibold uppercase tracking-wide", isDark ? "text-white/50" : "text-slate-500")}>Execution Logs</div>
                      <div className={cn("max-h-[320px] space-y-2 overflow-auto rounded-lg border p-3 text-xs", isDark ? "border-white/10 bg-black/40" : "border-slate-200 bg-slate-50") }>
                        {visibleLogs.length === 0 ? (
                          <p className={cn(isDark ? "text-white/40" : "text-slate-500")}>No logs returned.</p>
                        ) : (
                          visibleLogs.map((line, idx) => (
                            <div key={`${line}-${idx}`} className="flex gap-2">
                              <span className={cn("w-7 shrink-0 text-right tabular-nums", isDark ? "text-white/40" : "text-slate-400")}>
                                {idx + 1}.
                              </span>
                              <p className={cn("leading-relaxed", isDark ? "text-white/80" : "text-slate-700")}>{line}</p>
                            </div>
                          ))
                        )}
                      </div>
                      {totalDisplayLogs > visibleLogs.length ? (
                        <p className={cn("mt-2 text-xs", isDark ? "text-white/50" : "text-slate-500")}>
                          Showing first {visibleLogs.length} of {totalDisplayLogs} log lines.
                        </p>
                      ) : null}
                    </div>
                      </>
                    ) : null}
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
    </div>
  );
}