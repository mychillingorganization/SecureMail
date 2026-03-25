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

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";

function isValidEml(file: File | null): file is File {
  return Boolean(file && file.name.toLowerCase().endsWith(".eml"));
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
  const [file, setFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [userAcceptsDanger, setUserAcceptsDanger] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);

  const status = useMemo(() => {
    if (!result) return null;
    return statusTone(result.final_status);
  }, [result]);

  const visibleLogs = useMemo(() => {
    if (!result?.execution_logs?.length) return [];
    // Avoid rendering very large log payloads in one paint.
    return result.execution_logs.slice(0, 120);
  }, [result]);

  const selectFile = (candidate: File | null) => {
    if (!candidate) {
      return;
    }

    if (!isValidEml(candidate)) {
      setError("Only .eml files are supported.");
      return;
    }

    setError(null);
    setFile(candidate);
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setDragActive(false);
    selectFile(event.dataTransfer.files?.[0] ?? null);
  };

  const handleUpload = async () => {
    if (!isValidEml(file)) {
      setError("Select a valid .eml file before scanning.");
      return;
    }

    setError(null);
    setIsUploading(true);
    const uploadStartTime = Date.now();

    const endpoint = scanMode === "llm" ? "/api/v1/scan-upload-llm" : "/api/v1/scan-upload";
    const formData = new FormData();
    formData.append("file", file);
    formData.append("user_accepts_danger", String(userAcceptsDanger));

    try {
      const controller = new AbortController();
      // 5 minute timeout for large file uploads
      const timeoutId = setTimeout(() => controller.abort(), 300000);

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
      const participants = await extractSenderReceiver(file);

      // Save to PostgreSQL history truly non-blocking.
      void saveScanToHistory({
        scan_mode: scanMode,
        file_name: file.name,
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
                  <p className="text-sm font-medium">Drag and drop your .eml file here</p>
                  <p className={cn("mt-1 text-xs", isDark ? "text-white/50" : "text-slate-500")}>or browse from your computer</p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".eml"
                    className="hidden"
                    onChange={(event) => selectFile(event.target.files?.[0] ?? null)}
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

                {file ? (
                  <div className={cn("flex items-center justify-between rounded-lg border px-4 py-3", isDark ? "border-white/15 bg-white/5" : "border-slate-200 bg-white") }>
                    <div className="flex items-center gap-2 text-sm">
                      <FileText className="h-4 w-4" />
                      <span className="max-w-[260px] truncate">{file.name}</span>
                    </div>
                    <span className={cn("text-xs", isDark ? "text-white/50" : "text-slate-500")}>{(file.size / 1024).toFixed(1)} KB</span>
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
                    "Scan Email"
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
                {!result ? (
                  <div className={cn("rounded-lg border border-dashed p-6 text-sm", isDark ? "border-white/15 text-white/60" : "border-slate-300 text-slate-500") }>
                    Upload an email and run scan to see real backend results.
                  </div>
                ) : (
                  <>
                    <div className="flex items-center gap-2">
                      {status === "safe" ? <ShieldCheck className="h-5 w-5 text-emerald-500" /> : null}
                      {status === "warning" ? <ShieldQuestion className="h-5 w-5 text-amber-500" /> : null}
                      {status === "danger" ? <ShieldAlert className="h-5 w-5 text-red-500" /> : null}
                      <Badge variant={status === "danger" ? "destructive" : "default"}>{result.final_status}</Badge>
                      <span className={cn("text-xs", isDark ? "text-white/60" : "text-slate-500")}>Issues: {result.issue_count}</span>
                    </div>

                    {result.termination_reason ? (
                      <div className={cn("rounded-md border px-3 py-2 text-sm", isDark ? "border-amber-400/30 bg-amber-500/10 text-amber-100" : "border-amber-200 bg-amber-50 text-amber-800") }>
                        {result.termination_reason}
                      </div>
                    ) : null}

                    {(result.ai_reason || result.ai_summary || result.ai_classify) ? (
                      <div className={cn("space-y-3 rounded-lg border p-4", isDark ? "border-blue-400/20 bg-blue-500/10" : "border-blue-200 bg-blue-50") }>
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-semibold">🤖 LLM Analysis</span>
                          <span className={cn("text-xs", isDark ? "text-blue-200" : "text-blue-700") }>
                            {result.ai_provider ?? "AI"}
                            {typeof result.ai_confidence_percent === "number" ? ` - ${result.ai_confidence_percent}%` : ""}
                          </span>
                        </div>
                        
                        {result.ai_classify ? (
                          <div>
                            <p className={cn("text-xs font-medium mb-1", isDark ? "text-white/60" : "text-slate-600")}>Classification</p>
                            <p className={cn("text-sm font-bold capitalize", result.ai_classify === "safe" ? (isDark ? "text-emerald-300" : "text-emerald-700") : (isDark ? "text-rose-300" : "text-rose-700"))}>
                              {result.ai_classify}
                            </p>
                          </div>
                        ) : null}
                        
                        {result.ai_reason ? (
                          <div>
                            <p className={cn("text-xs font-medium mb-1", isDark ? "text-white/60" : "text-slate-600")}>Reason</p>
                            <p className="text-sm leading-relaxed">{result.ai_reason}</p>
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
                            <p key={`${line}-${idx}`} className={cn("leading-relaxed", isDark ? "text-white/80" : "text-slate-700")}>{line}</p>
                          ))
                        )}
                      </div>
                      {result.execution_logs.length > visibleLogs.length ? (
                        <p className={cn("mt-2 text-xs", isDark ? "text-white/50" : "text-slate-500")}>
                          Showing first {visibleLogs.length} of {result.execution_logs.length} log lines.
                        </p>
                      ) : null}
                    </div>
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