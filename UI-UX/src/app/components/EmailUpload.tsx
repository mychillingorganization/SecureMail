import { useRef, useState, type DragEvent } from "react";
import { Upload, Loader2 } from "lucide-react";
import { useTheme } from "./ThemeContext";
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

const API_BASE_URL = "http://localhost:8080";

function isValidEml(file: File | null): file is File {
  return Boolean(file && file.name.toLowerCase().endsWith(".eml"));
}

export function EmailUpload() {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [scanMode, setScanMode] = useState<ScanMode>("rule");
  const [file, setFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const handleDrag = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles?.length) {
      setFile(droppedFiles[0]);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!isValidEml(file)) {
      setUploadMessage({ type: "error", text: "Select a valid .eml file before scanning." });
      return;
    }

    setUploadMessage(null);
    setIsUploading(true);
    const uploadStartTime = Date.now();

    const endpoint = scanMode === "llm" ? "/api/v1/scan-upload-llm" : "/api/v1/scan-upload";
    const formData = new FormData();
    formData.append("file", file);
    formData.append("user_accepts_danger", "false");

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 300000);

      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error("Scan request failed");
      }

      const payload = (await response.json()) as ScanResponse;
      const durationMs = Date.now() - uploadStartTime;
      const participants = await extractSenderReceiver(file);

      // Save to history
      await saveScanToHistory({
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
      });

      setUploadMessage({
        type: "success",
        text: `✅ Email scanned successfully! Status: ${payload.final_status}`,
      });
      setFile(null);
    } catch (error) {
      setUploadMessage({
        type: "error",
        text: `Error: ${error instanceof Error ? error.message : "Unknown error"}`,
      });
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className={`rounded-lg border p-6 ${isDark ? "border-white/10 bg-black/40 backdrop-blur-xl" : "border-slate-200 bg-white/80"}`}>
      <h3 className={`mb-4 text-lg font-semibold ${isDark ? "text-white" : "text-slate-900"}`}>
        📧 Check Email
      </h3>

      {/* Mode Selection */}
      <div className="mb-4 flex gap-4">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="radio"
            value="rule"
            checked={scanMode === "rule"}
            onChange={(e) => setScanMode(e.target.value as ScanMode)}
            className="h-4 w-4"
          />
          <span className={`text-sm font-medium ${isDark ? "text-white/80" : "text-slate-700"}`}>
            Rule-Based (Fast)
          </span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="radio"
            value="llm"
            checked={scanMode === "llm"}
            onChange={(e) => setScanMode(e.target.value as ScanMode)}
            className="h-4 w-4"
          />
          <span className={`text-sm font-medium ${isDark ? "text-white/80" : "text-slate-700"}`}>
            LLM Deep-Dive (Detailed)
          </span>
        </label>
      </div>

      {/* Drag Drop Area */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`mb-4 cursor-pointer rounded-lg border-2 border-dashed p-8 text-center transition-colors ${
          dragActive
            ? isDark
              ? "border-blue-400 bg-blue-500/10"
              : "border-blue-400 bg-blue-50"
            : isDark
            ? "border-white/10 hover:border-white/20"
            : "border-slate-300 hover:border-slate-400"
        }`}
      >
        <Upload className={`mx-auto mb-2 h-6 w-6 ${isDark ? "text-white/40" : "text-slate-400"}`} />
        <p className={`text-sm font-medium ${isDark ? "text-white/60" : "text-slate-600"}`}>
          {file ? `📄 ${file.name}` : "Drag & drop .eml file or click to browse"}
        </p>
      </div>

      <input
        ref={fileInputRef}
        type="file"
        accept=".eml"
        onChange={handleFileSelect}
        className="hidden"
      />

      {/* Upload Button */}
      <button
        onClick={handleUpload}
        disabled={!file || isUploading}
        className={`w-full rounded-lg py-2 font-medium transition-colors ${
          isUploading || !file
            ? isDark
              ? "bg-white/5 text-white/40 cursor-not-allowed"
              : "bg-slate-100 text-slate-400 cursor-not-allowed"
            : isDark
            ? "bg-blue-600 text-white hover:bg-blue-500"
            : "bg-blue-600 text-white hover:bg-blue-700"
        }`}
      >
        {isUploading ? (
          <div className="flex items-center justify-center gap-2">
            <Loader2 className="h-4 w-4 animate-spin" />
            Scanning...
          </div>
        ) : (
          "Scan Email"
        )}
      </button>

      {/* Status Message */}
      {uploadMessage && (
        <div
          className={`mt-4 rounded-lg p-3 text-sm ${
            uploadMessage.type === "success"
              ? isDark
                ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20"
                : "bg-emerald-50 text-emerald-700 border border-emerald-200"
              : isDark
              ? "bg-rose-500/10 text-rose-300 border border-rose-500/20"
              : "bg-rose-50 text-rose-700 border border-rose-200"
          }`}
        >
          {uploadMessage.text}
        </div>
      )}
    </div>
  );
}
