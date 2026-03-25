import { useEffect, useMemo, useRef, useState, type DragEvent } from "react";
import { useNavigate } from "react-router";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { useTheme } from "./ThemeContext";
import { Button } from "./ui/button";
import { Textarea } from "./ui/textarea";
import { cn } from "./ui/utils";
import { detectChatIntent } from "../api/chat";
import { useChat } from "../hooks/useChat";

type LocalIntentDetection = {
  detectedTool: string | null;
  shouldTriggerAttachmentScan: boolean;
  highConfidence: boolean;
};

const CHAT_DRAFT_STORAGE_KEY = "securemail.chat.draft";
const CHAT_CONTEXT_MODE_STORAGE_KEY = "securemail.chat.contextMode";
const CHAT_SCAN_MODE_STORAGE_KEY = "securemail.chat.scanMode";
const CHAT_COMPOSER_NOTICE_STORAGE_KEY = "securemail.chat.composerNotice";


function readSessionValue(key: string): string {
  if (typeof window === "undefined") return "";
  return window.sessionStorage.getItem(key) ?? "";
}


function writeSessionValue(key: string, value: string): void {
  if (typeof window === "undefined") return;
  if (value.trim().length > 0) {
    window.sessionStorage.setItem(key, value);
  } else {
    window.sessionStorage.removeItem(key);
  }
}


function readContextMode(): "general" | "scan" {
  return readSessionValue(CHAT_CONTEXT_MODE_STORAGE_KEY) === "scan" ? "scan" : "general";
}


function readScanMode(): "rule" | "llm" {
  return readSessionValue(CHAT_SCAN_MODE_STORAGE_KEY) === "rule" ? "rule" : "llm";
}

function detectLocalIntent(message: string, hasPendingAttachment: boolean): LocalIntentDetection {
  const text = message.trim().toLowerCase();
  if (!text) {
    return {
      detectedTool: null,
      shouldTriggerAttachmentScan: false,
      highConfidence: false,
    };
  }

  const hasUrl = /https?:\/\/[^\s]+/i.test(text);
  const hasFileHash = /\b[a-f0-9]{64}\b/i.test(text);
  const hasEmailContentMarker = /(email content|mail content|email body|mail body)/i.test(text);
  const hasCheckIntent = /(check|scan|analy[sz]e|analyse|verify|safe|phishing|malicious|risk|status|is)/i.test(text);

  if (hasEmailContentMarker) {
    return {
      detectedTool: "check_email_content_ai",
      shouldTriggerAttachmentScan: false,
      highConfidence: true,
    };
  }

  if (hasUrl && hasCheckIntent) {
    return {
      detectedTool: "check_url_reputation",
      shouldTriggerAttachmentScan: false,
      highConfidence: true,
    };
  }

  if (hasFileHash && hasCheckIntent) {
    return {
      detectedTool: "check_file_hash_reputation",
      shouldTriggerAttachmentScan: false,
      highConfidence: true,
    };
  }

  const attachmentScanIntent = /(scan|analy[sz]e|analyse|inspect|check|triage|verdict|risk|safe|unsafe|malicious|phishing|is this safe|is it safe|is this file safe)/i.test(text);
  if (hasPendingAttachment && attachmentScanIntent) {
    return {
      detectedTool: null,
      shouldTriggerAttachmentScan: true,
      highConfidence: true,
    };
  }

  return {
    detectedTool: null,
    shouldTriggerAttachmentScan: false,
    highConfidence: false,
  };
}

export function ChatPage() {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const navigate = useNavigate();

  const {
    conversations,
    activeConversationId,
    activeMessages,
    isLoadingConversations,
    isSending,
    isUploadingEml,
    error,
    setActiveConversationId,
    loadConversations,
    loadMessages,
    submitMessage,
    submitAttachmentUpload,
    startNewConversation,
    removeConversation,
  } = useChat();

  const [draft, setDraft] = useState(() => readSessionValue(CHAT_DRAFT_STORAGE_KEY));
  const [contextMode, setContextMode] = useState<"general" | "scan">(() => readContextMode());
  const [dragActive, setDragActive] = useState(false);
  const [scanMode, setScanMode] = useState<"rule" | "llm">(() => readScanMode());
  const [pendingEmlFile, setPendingEmlFile] = useState<File | null>(null);
  const [composerNotice, setComposerNotice] = useState<string | null>(() => {
    const value = readSessionValue(CHAT_COMPOSER_NOTICE_STORAGE_KEY);
    return value || null;
  });
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const handleEmlCandidate = async (candidate: File | null) => {
    if (!candidate) return;
    setPendingEmlFile(candidate);
    setComposerNotice(`Attached ${candidate.name}. Ask me to scan it.`);
  };

  const handleDropUpload = async (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setDragActive(false);
    await handleEmlCandidate(event.dataTransfer.files?.[0] ?? null);
  };

  useEffect(() => {
    void loadConversations();
  }, [loadConversations]);

  useEffect(() => {
    if (!activeConversationId) return;
    void loadMessages(activeConversationId);
  }, [activeConversationId, loadMessages]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [activeConversationId, activeMessages.length, isSending, isUploadingEml]);

  useEffect(() => {
    writeSessionValue(CHAT_DRAFT_STORAGE_KEY, draft);
  }, [draft]);

  useEffect(() => {
    writeSessionValue(CHAT_CONTEXT_MODE_STORAGE_KEY, contextMode);
  }, [contextMode]);

  useEffect(() => {
    writeSessionValue(CHAT_SCAN_MODE_STORAGE_KEY, scanMode);
  }, [scanMode]);

  useEffect(() => {
    writeSessionValue(CHAT_COMPOSER_NOTICE_STORAGE_KEY, composerNotice ?? "");
  }, [composerNotice]);

  const activeTitle = useMemo(() => {
    if (!activeConversationId) return "New Conversation";
    const found = conversations.find((item) => item.id === activeConversationId);
    return found?.title ?? "Conversation";
  }, [activeConversationId, conversations]);

  const onSend = async () => {
    const text = draft.trim();
    if (!text || isSending) return;

    const localIntent = detectLocalIntent(text, Boolean(pendingEmlFile));
    let detectedTool: string | null = localIntent.detectedTool;
    let shouldTriggerAttachmentScan = localIntent.shouldTriggerAttachmentScan;

    if (!localIntent.highConfidence) {
      try {
        const intent = await detectChatIntent({
          message: text,
          has_pending_attachment: Boolean(pendingEmlFile),
        });
        detectedTool = intent.detected_tool;
        shouldTriggerAttachmentScan = intent.should_trigger_attachment_scan;
      } catch {
        // Keep local result when intent API is unavailable.
      }
    }

    if (pendingEmlFile) {
      if (!shouldTriggerAttachmentScan) {
        setComposerNotice("Message sent. Attachment is still pending; ask to scan it when ready.");
      } else {
        setDraft("");
        setComposerNotice(null);
        await submitAttachmentUpload(pendingEmlFile, scanMode, false, text);
        setPendingEmlFile(null);
        return;
      }
    }

    setDraft("");
    setComposerNotice(null);
    const modeForMessage = detectedTool ? "scan" : contextMode;
    await submitMessage(text, modeForMessage);
  };

  const renderReasonTrace = (payload: Record<string, unknown>) => {
    const finalStatus = typeof payload.final_status === "string" ? payload.final_status : null;
    const issueCount = typeof payload.issue_count === "number" ? payload.issue_count : null;
    const confidence = typeof payload.ai_confidence_percent === "number" ? payload.ai_confidence_percent : null;
    const aiClassify = typeof payload.ai_classify === "string" ? payload.ai_classify : null;
    const aiReason = typeof payload.ai_reason === "string" ? payload.ai_reason : null;
    const aiSummary = typeof payload.ai_summary === "string" ? payload.ai_summary : null;

    const cotSteps = Array.isArray(payload.ai_cot_steps)
      ? payload.ai_cot_steps.filter((step): step is string => typeof step === "string" && step.trim().length > 0)
      : [];
    const toolTrace = Array.isArray(payload.tool_trace)
      ? payload.tool_trace.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object")
      : [];
    const executionLogs = Array.isArray(payload.execution_logs)
      ? payload.execution_logs.filter((log): log is string => typeof log === "string" && log.trim().length > 0)
      : [];

    const displaySteps = cotSteps.length > 0 ? cotSteps : executionLogs.slice(0, 8);

    return (
      <details className="mt-2 text-[11px] opacity-90">
        <summary className="cursor-pointer font-medium">Reasoning Trace</summary>
        <div className={cn("mt-2 space-y-2 rounded border p-2", isDark ? "border-white/10 bg-black/20" : "border-slate-200 bg-white/60")}>
          <div className="flex flex-wrap gap-2">
            {finalStatus ? <span className="rounded-full bg-blue-500/15 px-2 py-0.5">Status: {finalStatus}</span> : null}
            {typeof issueCount === "number" ? <span className="rounded-full bg-amber-500/15 px-2 py-0.5">Issues: {issueCount}</span> : null}
            {aiClassify ? <span className="rounded-full bg-emerald-500/15 px-2 py-0.5">Classify: {aiClassify}</span> : null}
            {typeof confidence === "number" ? <span className="rounded-full bg-violet-500/15 px-2 py-0.5">Confidence: {confidence}%</span> : null}
          </div>

          {aiReason ? <p className="text-[11px] leading-relaxed"><span className="font-medium">Reason:</span> {aiReason}</p> : null}
          {!aiReason && aiSummary ? <p className="text-[11px] leading-relaxed"><span className="font-medium">Summary:</span> {aiSummary}</p> : null}

          {toolTrace.length > 0 ? (
            <div>
              <p className="mb-1 font-medium">Tool-by-Tool Trace</p>
              <div className="space-y-2">
                {toolTrace.map((entry, idx) => {
                  const step = typeof entry.step === "number" ? entry.step : idx + 1;
                  const toolName = typeof entry.tool_name === "string" ? entry.tool_name : "unknown";
                  const argsPreview = typeof entry.tool_args_preview === "string" ? entry.tool_args_preview : null;
                  const resultPreview = typeof entry.tool_result_preview === "string" ? entry.tool_result_preview : null;
                  const reviewStatus = typeof entry.review_status === "string" ? entry.review_status : null;

                  return (
                    <div key={`${step}-${toolName}-${idx}`} className={cn("rounded border p-2", isDark ? "border-white/10 bg-white/5" : "border-slate-200 bg-slate-50") }>
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">Step {step}: {toolName}</span>
                        {reviewStatus ? <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] uppercase tracking-wide">{reviewStatus}</span> : null}
                      </div>
                      {argsPreview ? <p className="mt-1 break-words"><span className="font-medium">Args:</span> {argsPreview}</p> : null}
                      {resultPreview ? <p className="mt-1 break-words"><span className="font-medium">Result:</span> {resultPreview}</p> : null}
                    </div>
                  );
                })}
              </div>
            </div>
          ) : null}

          {toolTrace.length === 0 && displaySteps.length > 0 ? (
            <div>
              <p className="mb-1 font-medium">Trace Steps</p>
              <ol className="space-y-1">
                {displaySteps.map((step, idx) => (
                  <li key={`${idx}-${step.slice(0, 16)}`} className="flex gap-2 leading-relaxed">
                    <span className="opacity-70">{idx + 1}.</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          ) : null}
        </div>
      </details>
    );
  };

  const renderMessageContent = (content: string, isAssistant: boolean) => {
    if (!isAssistant) {
      return <p className="whitespace-pre-wrap text-sm leading-relaxed">{content}</p>;
    }

    return (
      <div className="text-sm leading-relaxed">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={{
            p: ({ children }) => <p className="mb-2 last:mb-0 whitespace-pre-wrap">{children}</p>,
            ul: ({ children }) => <ul className="mb-2 list-disc pl-5 space-y-1">{children}</ul>,
            ol: ({ children }) => <ol className="mb-2 list-decimal pl-5 space-y-1">{children}</ol>,
            li: ({ children }) => <li>{children}</li>,
            h1: ({ children }) => <h1 className="mb-2 text-base font-semibold">{children}</h1>,
            h2: ({ children }) => <h2 className="mb-2 text-sm font-semibold">{children}</h2>,
            h3: ({ children }) => <h3 className="mb-1 text-sm font-medium">{children}</h3>,
            strong: ({ children }) => <strong className="font-semibold">{children}</strong>,
            em: ({ children }) => <em className="italic">{children}</em>,
            code: ({ children }) => (
              <code className={cn("rounded px-1 py-0.5 text-[12px]", isDark ? "bg-white/15" : "bg-slate-200")}>{children}</code>
            ),
            pre: ({ children }) => (
              <pre className={cn("mb-2 overflow-x-auto rounded p-2 text-[12px]", isDark ? "bg-black/30" : "bg-slate-200")}>{children}</pre>
            ),
            a: ({ href, children }) => (
              <a href={href} target="_blank" rel="noreferrer" className="underline decoration-dotted">
                {children}
              </a>
            ),
            blockquote: ({ children }) => (
              <blockquote className={cn("my-2 border-l-2 pl-3 italic", isDark ? "border-white/30" : "border-slate-400")}>{children}</blockquote>
            ),
          }}
        >
          {content}
        </ReactMarkdown>
      </div>
    );
  };

  return (
    <div className={cn("relative flex h-screen w-full overflow-hidden", isDark ? "bg-[#030308] text-white" : "bg-slate-50 text-slate-900")}>
      <Sidebar />

      <div className="relative z-10 flex flex-1 flex-col overflow-hidden">
        <Header />

        <main className="flex-1 min-h-0 overflow-hidden p-6 md:p-8">
          <div className="mx-auto grid h-full min-h-0 max-w-7xl gap-6 lg:grid-cols-[280px_1fr]">
            <section className={cn("flex h-full min-h-0 flex-col rounded-xl border", isDark ? "border-white/10 bg-black/30" : "border-slate-200 bg-white") }>
              <div className="flex items-center justify-between border-b p-4">
                <h2 className="text-sm font-semibold">Conversations</h2>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    void startNewConversation();
                    setDraft("");
                    setPendingEmlFile(null);
                    setComposerNotice("Started a new chat.");
                  }}
                >
                  <span className="text-sm leading-none">+</span>
                </Button>
              </div>

              <div className="min-h-0 flex-1 overflow-auto p-3">
                {isLoadingConversations ? (
                  <p className={cn("text-xs", isDark ? "text-white/50" : "text-slate-500")}>Loading chats...</p>
                ) : conversations.length === 0 ? (
                  <p className={cn("text-xs", isDark ? "text-white/50" : "text-slate-500")}>No history yet. Start a new chat.</p>
                ) : (
                  <div className="space-y-2">
                    {conversations.map((conversation) => (
                      <div
                        key={conversation.id}
                        className={cn(
                          "w-full rounded-md border p-2 text-sm transition-colors",
                          activeConversationId === conversation.id
                            ? isDark
                              ? "border-blue-400/40 bg-blue-500/10"
                              : "border-blue-200 bg-blue-50"
                            : isDark
                            ? "border-white/10 hover:bg-white/5"
                            : "border-slate-200 hover:bg-slate-50",
                        )}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <button
                            type="button"
                            onClick={() => setActiveConversationId(conversation.id)}
                            className="min-w-0 flex-1 text-left"
                          >
                            <div className="truncate font-medium">{conversation.title}</div>
                            <div className={cn("mt-1 text-xs", isDark ? "text-white/50" : "text-slate-500")}>
                              {new Date(conversation.last_message_at).toLocaleString()}
                            </div>
                          </button>

                          <button
                            type="button"
                            aria-label="Delete conversation"
                            className={cn("rounded p-1", isDark ? "hover:bg-white/10" : "hover:bg-slate-200")}
                            onClick={(event) => {
                              event.preventDefault();
                              event.stopPropagation();
                              void removeConversation(conversation.id);
                            }}
                          >
                            <span className="text-xs font-semibold">X</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </section>

            <section className={cn("flex h-full min-h-0 flex-col rounded-xl border", isDark ? "border-white/10 bg-black/30" : "border-slate-200 bg-white") }>
              <div className="border-b px-5 py-4">
                <div className="flex items-center justify-between gap-3">
                  <h2 className="text-base font-semibold">{activeTitle}</h2>
                  <Button type="button" variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}>
                    Upload File
                  </Button>
                </div>
                <p className={cn("text-xs", isDark ? "text-white/50" : "text-slate-500")}>
                  Ask for KPI, risky senders/domains, file risk, URL threat, or AI confidence summaries. You can upload .eml or other files directly here and see trace output.
                </p>
              </div>

              <div className="min-h-0 flex-1 space-y-4 overflow-auto p-5">
                <div
                  className={cn(
                    "rounded-lg border border-dashed p-3",
                    dragActive
                      ? isDark
                        ? "border-blue-400 bg-blue-500/10"
                        : "border-blue-500 bg-blue-50"
                      : isDark
                      ? "border-white/15 bg-white/5"
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
                  onDrop={(event) => {
                    void handleDropUpload(event);
                  }}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    className="hidden"
                    onChange={(event) => {
                      void handleEmlCandidate(event.target.files?.[0] ?? null);
                    }}
                  />
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-xs font-semibold uppercase">File</span>
                      <span>{pendingEmlFile ? `Attached: ${pendingEmlFile.name}` : "Drop file here or attach to this chat"}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setScanMode("rule")}
                        className={cn("rounded-full px-2 py-1 text-xs", scanMode === "rule" ? "bg-blue-600 text-white" : isDark ? "bg-white/10" : "bg-slate-100")}
                      >
                        Rule
                      </button>
                      <button
                        type="button"
                        onClick={() => setScanMode("llm")}
                        className={cn("rounded-full px-2 py-1 text-xs", scanMode === "llm" ? "bg-blue-600 text-white" : isDark ? "bg-white/10" : "bg-slate-100")}
                      >
                        LLM
                      </button>
                      <Button type="button" variant="outline" size="sm" onClick={() => fileInputRef.current?.click()} disabled={isUploadingEml}>
                        {isUploadingEml ? "Uploading..." : "Attach File"}
                      </Button>
                      {pendingEmlFile ? (
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setPendingEmlFile(null);
                            setComposerNotice("Attachment removed.");
                          }}
                        >
                          Remove
                        </Button>
                      ) : null}
                    </div>
                  </div>
                </div>

                {activeMessages.length === 0 ? (
                  <div className={cn("rounded-lg border border-dashed p-6 text-sm", isDark ? "border-white/10 text-white/60" : "border-slate-300 text-slate-500")}>
                    <p className="font-medium">Start chatting with SecureMail Assistant</p>
                    <p className="mt-2">Example: "Show KPI summary for last 7 days"</p>
                    <Button
                      type="button"
                      variant="outline"
                      className="mt-4"
                      onClick={() => navigate("/scanner")}
                    >
                      Go to Check Email Upload
                    </Button>
                  </div>
                ) : (
                  activeMessages.map((message) => (
                    <div key={message.id} className={cn("flex", message.role === "user" ? "justify-end" : "justify-start")}>
                      <div
                        className={cn(
                          "max-w-[80%] rounded-xl px-4 py-3",
                          message.role === "user"
                            ? isDark
                              ? "bg-blue-600 text-white"
                              : "bg-blue-600 text-white"
                            : isDark
                            ? "bg-white/10 text-white/90"
                            : "bg-slate-100 text-slate-800",
                        )}
                      >
                        <div className="mb-1 flex items-center gap-2 text-xs opacity-80">
                          <span>{message.role === "user" ? "You" : "Assistant"}</span>
                        </div>
                        {renderMessageContent(message.content, message.role !== "user")}
                        {message.tool_name ? (
                          <div className="mt-2 flex items-center gap-1 text-[11px] opacity-80">
                            <span>Tool: {message.tool_name}</span>
                          </div>
                        ) : null}
                        {message.tool_payload && typeof message.tool_payload === "object"
                          ? renderReasonTrace(message.tool_payload)
                          : null}
                      </div>
                    </div>
                  ))
                )}
                <div ref={messagesEndRef} />
              </div>

              <div className="border-t p-4">
                <div className="mb-2 flex items-center gap-2 text-xs">
                  <button
                    type="button"
                    onClick={() => setContextMode("general")}
                    className={cn("rounded-full px-2 py-1", contextMode === "general" ? "bg-blue-600 text-white" : isDark ? "bg-white/10" : "bg-slate-100")}
                  >
                    General
                  </button>
                  <button
                    type="button"
                    onClick={() => setContextMode("scan")}
                    className={cn("rounded-full px-2 py-1", contextMode === "scan" ? "bg-blue-600 text-white" : isDark ? "bg-white/10" : "bg-slate-100")}
                  >
                    Scan-Aware
                  </button>
                </div>

                <div className="flex items-end gap-2">
                  <Textarea
                    value={draft}
                    onChange={(event) => setDraft(event.target.value)}
                    placeholder="Ask for a security summary or follow-up question..."
                    className="min-h-[72px]"
                    onKeyDown={(event) => {
                      if (event.key === "Enter" && !event.shiftKey) {
                        event.preventDefault();
                        void onSend();
                      }
                    }}
                  />
                  <Button type="button" onClick={() => void onSend()} disabled={isSending || isUploadingEml || !draft.trim()}>
                    <span className="text-xs font-semibold uppercase">Send</span>
                  </Button>
                </div>

                {composerNotice ? <p className="mt-2 text-xs text-blue-500">{composerNotice}</p> : null}
                {error ? <p className="mt-2 text-xs text-red-500">{error}</p> : null}
              </div>
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}
