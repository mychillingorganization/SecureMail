import { X } from "lucide-react";
import { useTheme } from "./ThemeContext";
import type { ScanHistoryItem } from "../api/scanHistory";

interface ScanDetailProps {
  scan: ScanHistoryItem | null;
  onClose: () => void;
}

export function ScanDetail({ scan, onClose }: ScanDetailProps) {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  if (!scan) return null;

  const isLLM = scan.scan_mode === "llm";
  const isSafe = scan.final_status === "PASS";

  return (
    <div className={`fixed inset-0 z-50 overflow-y-auto ${isDark ? "bg-black/40" : "bg-black/20"} backdrop-blur-sm`}>
      <div className="flex min-h-screen items-center justify-center p-4">
        <div
          className={`relative w-full max-w-2xl rounded-lg border shadow-2xl ${
            isDark
              ? "border-white/10 bg-[#0a0a1a]"
              : "border-slate-200 bg-white"
          }`}
        >
          {/* Header */}
          <div
            className={`sticky top-0 flex items-center justify-between border-b px-6 py-4 backdrop-blur-xl ${
              isDark ? "border-white/5 bg-black/50" : "border-slate-100 bg-white/50"
            }`}
          >
            <div className="flex-1">
              <h2
                className={`text-lg font-bold ${
                  isDark ? "text-white" : "text-slate-900"
                }`}
              >
                {scan.file_name}
              </h2>
              <p
                className={`text-xs font-medium ${
                  isDark ? "text-white/50" : "text-slate-500"
                }`}
              >
                {new Date(scan.timestamp).toLocaleString()}
              </p>
            </div>
            <button
              onClick={onClose}
              className={`rounded-md p-2 transition-colors ${
                isDark
                  ? "hover:bg-white/10 text-white/60 hover:text-white/90"
                  : "hover:bg-slate-100 text-slate-600 hover:text-slate-900"
              }`}
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Content */}
          <div className={`overflow-y-auto max-h-[calc(100vh-200px)] p-6 space-y-6 ${isDark ? "text-white/80" : "text-slate-700"}`}>
            {/* Status Section */}
            <div
              className={`rounded-lg border p-4 ${
                isDark
                  ? "border-white/5 bg-white/5"
                  : "border-slate-200 bg-slate-50"
              }`}
            >
              <h3
                className={`mb-3 text-sm font-semibold uppercase tracking-wide ${
                  isDark ? "text-white/70" : "text-slate-600"
                }`}
              >
                Scan Summary
              </h3>
              <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
                <div>
                  <p className={`text-xs ${isDark ? "text-white/50" : "text-slate-500"}`}>
                    Status
                  </p>
                  <p
                    className={`font-bold text-sm ${
                      isSafe
                        ? isDark
                          ? "text-emerald-400"
                          : "text-emerald-600"
                        : isDark
                        ? "text-rose-400"
                        : "text-rose-600"
                    }`}
                  >
                    {scan.final_status}
                  </p>
                </div>
                <div>
                  <p className={`text-xs ${isDark ? "text-white/50" : "text-slate-500"}`}>
                    Mode
                  </p>
                  <p className="font-bold text-sm">
                    {scan.scan_mode === "llm" ? "LLM Deep-Dive" : "Rule-Based"}
                  </p>
                </div>
                <div>
                  <p className={`text-xs ${isDark ? "text-white/50" : "text-slate-500"}`}>
                    Issues Found
                  </p>
                  <p className="font-bold text-sm">{scan.issue_count}</p>
                </div>
                <div>
                  <p className={`text-xs ${isDark ? "text-white/50" : "text-slate-500"}`}>
                    Duration
                  </p>
                  <p className="font-bold text-sm">
                    {(scan.duration_ms / 1000).toFixed(1)}s
                  </p>
                </div>
              </div>
              <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
                <div>
                  <p className={`text-xs ${isDark ? "text-white/50" : "text-slate-500"}`}>Sender</p>
                  <p className="font-medium text-sm break-words">{scan.sender ?? "Unknown"}</p>
                </div>
                <div>
                  <p className={`text-xs ${isDark ? "text-white/50" : "text-slate-500"}`}>Receiver</p>
                  <p className="font-medium text-sm break-words">{scan.receiver ?? "Unknown"}</p>
                </div>
              </div>
            </div>

            {/* AI Analysis (LLM only) */}
            {isLLM && (
              <div
                className={`rounded-lg border p-4 ${
                  isDark
                    ? "border-blue-400/20 bg-blue-500/10"
                    : "border-blue-200 bg-blue-50"
                }`}
              >
                <div className="flex items-center justify-between mb-3">
                  <h3
                    className={`text-sm font-semibold ${
                      isDark ? "text-white" : "text-slate-900"
                    }`}
                  >
                    🤖 LLM Analysis
                  </h3>
                  <span className={`text-xs ${isDark ? "text-blue-200" : "text-blue-700"}`}>
                    {scan.ai_confidence_percent !== null ? `${scan.ai_confidence_percent}%` : ""}
                  </span>
                </div>
                <div className="space-y-3">
                  {scan.ai_classify && (
                    <div>
                      <p
                        className={`text-xs font-medium mb-1 ${
                          isDark ? "text-white/60" : "text-slate-600"
                        }`}
                      >
                        Classification
                      </p>
                      <p
                        className={`text-sm font-bold capitalize ${
                          scan.ai_classify === "safe"
                            ? isDark
                              ? "text-emerald-300"
                              : "text-emerald-700"
                            : isDark
                            ? "text-rose-300"
                            : "text-rose-700"
                        }`}
                      >
                        {scan.ai_classify}
                      </p>
                    </div>
                  )}
                  {scan.ai_reason && (
                    <div>
                      <p
                        className={`text-xs font-medium mb-1 ${
                          isDark ? "text-white/60" : "text-slate-600"
                        }`}
                      >
                        Reason
                      </p>
                      <p className="text-sm leading-relaxed">
                        {scan.ai_reason}
                      </p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Execution Logs */}
            <div
              className={`rounded-lg border p-4 ${
                isDark
                  ? "border-white/5 bg-white/5"
                  : "border-slate-200 bg-slate-50"
              }`}
            >
              <h3
                className={`mb-3 text-sm font-semibold uppercase tracking-wide ${
                  isDark ? "text-white/70" : "text-slate-600"
                }`}
              >
                📋 Execution Logs
              </h3>
              <div
                className={`space-y-2 rounded font-mono text-xs overflow-x-auto ${
                  isDark
                    ? "bg-[#0a0a1a]/80 border border-white/5 p-3 text-white/60"
                    : "bg-white border border-slate-200 p-3 text-slate-600"
                }`}
              >
                {scan.execution_logs.length === 0 ? (
                  <p className={isDark ? "text-white/30" : "text-slate-400"}>
                    No logs available
                  </p>
                ) : (
                  scan.execution_logs.map((log, idx) => (
                    <div key={idx} className="whitespace-pre-wrap break-words">
                      {log}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* AI COT Steps (if available) */}
            {isLLM && scan.ai_cot_steps && scan.ai_cot_steps.length > 0 && (
              <div
                className={`rounded-lg border p-4 ${
                  isDark
                    ? "border-blue-500/20 bg-blue-500/10"
                    : "border-blue-200 bg-blue-50"
                }`}
              >
                <h3
                  className={`mb-3 text-sm font-semibold uppercase tracking-wide ${
                    isDark ? "text-blue-400" : "text-blue-700"
                  }`}
                >
                  🧠 AI Reasoning Steps
                </h3>
                <ol className="space-y-2">
                  {scan.ai_cot_steps.map((step, idx) => (
                    <li
                      key={idx}
                      className={`text-sm leading-relaxed ${
                        isDark ? "text-white/70" : "text-slate-700"
                      }`}
                    >
                      <span
                        className={`font-bold mr-2 ${
                          isDark
                            ? "text-blue-400"
                            : "text-blue-600"
                        }`}
                      >
                        {idx + 1}.
                      </span>
                      {step}
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>

          {/* Footer */}
          <div
            className={`border-t px-6 py-3 text-right ${
              isDark ? "border-white/5 bg-black/50" : "border-slate-100 bg-slate-50/50"
            }`}
          >
            <button
              onClick={onClose}
              className={`rounded-md px-4 py-2 text-sm font-medium transition-colors ${
                isDark
                  ? "bg-blue-600 text-white hover:bg-blue-500"
                  : "bg-blue-600 text-white hover:bg-blue-700"
              }`}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
