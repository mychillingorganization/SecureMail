export type ChatConversation = {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  last_message_at: string;
};

export type ChatMessage = {
  id: string;
  conversation_id: string;
  role: "user" | "assistant" | "tool";
  content: string;
  status: string;
  tool_name?: string | null;
  tool_payload?: Record<string, unknown> | null;
  created_at: string;
};

export type ChatMessagesResponse = {
  conversation_id: string;
  messages: ChatMessage[];
};

export type ChatSendResponse = {
  conversation: ChatConversation;
  user_message: ChatMessage;
  assistant_message: ChatMessage;
};

export type ChatIntentResponse = {
  detected_tool: string | null;
  should_trigger_attachment_scan: boolean;
  reason: string;
};

export type ChatStreamStartPayload = {
  conversation: ChatConversation;
  user_message: ChatMessage;
};

export type ChatStreamDonePayload = {
  conversation: ChatConversation;
  assistant_message: ChatMessage;
};

type ChatStreamHandlers = {
  onStart?: (payload: ChatStreamStartPayload) => void;
  onChunk?: (delta: string) => void;
  onDone?: (payload: ChatStreamDonePayload) => void;
};

const API_BASE_URL = (import.meta as { env?: Record<string, string | undefined> }).env?.VITE_API_BASE_URL || "http://localhost:8080";

function resolveStreamTimeoutMs(): number {
  const raw = (import.meta as { env?: Record<string, string | undefined> }).env?.VITE_CHAT_STREAM_TIMEOUT_MS;
  const parsed = raw ? Number.parseInt(raw, 10) : Number.NaN;
  if (Number.isFinite(parsed) && parsed > 0) {
    return parsed;
  }
  // Default to 10 minutes for slow tool/model paths.
  return 600000;
}

async function withTimeoutFetch(input: string, init: RequestInit, timeoutMs: number = 30000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(input, { ...init, signal: controller.signal });
    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      try {
        const payload = await response.json();
        detail = payload?.detail ?? detail;
      } catch {
        // Keep default detail.
      }
      throw new Error(detail);
    }
    return response;
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error(`Request timed out after ${Math.ceil(timeoutMs / 1000)}s. Please try again.`);
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function fetchChatConversations(limit: number = 20): Promise<ChatConversation[]> {
  const response = await withTimeoutFetch(`${API_BASE_URL}/api/v1/chat/conversations?limit=${limit}`, {
    method: "GET",
  });
  const payload = await response.json();
  return Array.isArray(payload) ? payload : [];
}

export async function createChatConversation(): Promise<ChatConversation> {
  const response = await withTimeoutFetch(`${API_BASE_URL}/api/v1/chat/conversations`, {
    method: "POST",
  });
  return (await response.json()) as ChatConversation;
}

export async function deleteChatConversation(conversationId: string): Promise<void> {
  await withTimeoutFetch(`${API_BASE_URL}/api/v1/chat/conversations/${encodeURIComponent(conversationId)}`, {
    method: "DELETE",
  });
}

export async function fetchChatMessages(
  conversationId: string,
  limit: number = 100,
  offset: number = 0,
): Promise<ChatMessagesResponse> {
  const url = `${API_BASE_URL}/api/v1/chat/messages?conversation_id=${encodeURIComponent(conversationId)}&limit=${limit}&offset=${offset}`;
  const response = await withTimeoutFetch(url, { method: "GET" });
  return (await response.json()) as ChatMessagesResponse;
}

export async function sendChatMessage(data: {
  message: string;
  conversation_id?: string | null;
  context_mode?: "general" | "scan";
}): Promise<ChatSendResponse> {
  const response = await withTimeoutFetch(`${API_BASE_URL}/api/v1/chat/send`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  }, 120000);

  return (await response.json()) as ChatSendResponse;
}

export async function sendChatMessageStream(
  data: {
    message: string;
    conversation_id?: string | null;
    context_mode?: "general" | "scan";
  },
  handlers: ChatStreamHandlers = {},
): Promise<void> {
  const controller = new AbortController();
  const timeoutMs = resolveStreamTimeoutMs();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/chat/send-stream`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
      signal: controller.signal,
    });

    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      try {
        const payload = await response.json();
        detail = payload?.detail ?? detail;
      } catch {
        // Keep default detail.
      }
      throw new Error(detail);
    }

    if (!response.body) {
      throw new Error("Streaming response has no body");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      const events = buffer.split("\n\n");
      buffer = events.pop() ?? "";

      for (const eventBlock of events) {
        const lines = eventBlock
          .split("\n")
          .map((line) => line.trim())
          .filter((line) => line.length > 0);

        const eventLine = lines.find((line) => line.startsWith("event:"));
        const dataLine = lines.find((line) => line.startsWith("data:"));
        if (!dataLine) continue;

        const eventName = eventLine ? eventLine.slice(6).trim() : "message";
        const jsonText = dataLine.slice(5).trim();
        if (!jsonText) continue;

        let payload: unknown;
        try {
          payload = JSON.parse(jsonText);
        } catch {
          continue;
        }

        if (eventName === "start" && handlers.onStart && payload && typeof payload === "object") {
          handlers.onStart(payload as ChatStreamStartPayload);
        } else if (eventName === "chunk" && handlers.onChunk && payload && typeof payload === "object") {
          const delta = (payload as { delta?: unknown }).delta;
          if (typeof delta === "string") {
            handlers.onChunk(delta);
          }
        } else if (eventName === "done" && handlers.onDone && payload && typeof payload === "object") {
          handlers.onDone(payload as ChatStreamDonePayload);
        }
      }
    }
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error(`Streaming request timed out after ${Math.ceil(timeoutMs / 1000)}s. Please try again.`);
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function detectChatIntent(data: {
  message: string;
  has_pending_attachment?: boolean;
}): Promise<ChatIntentResponse> {
  const response = await withTimeoutFetch(`${API_BASE_URL}/api/v1/chat/intent`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  }, 4000);

  return (await response.json()) as ChatIntentResponse;
}

export async function uploadChatEml(data: {
  file: File;
  conversation_id?: string | null;
  scan_mode?: "rule" | "llm";
  user_accepts_danger?: boolean;
  trigger_message?: string;
}): Promise<ChatSendResponse> {
  const formData = new FormData();
  formData.append("file", data.file);
  formData.append("scan_mode", data.scan_mode ?? "llm");
  formData.append("user_accepts_danger", String(Boolean(data.user_accepts_danger)));
  if (data.conversation_id) {
    formData.append("conversation_id", data.conversation_id);
  }
  if (data.trigger_message && data.trigger_message.trim()) {
    formData.append("trigger_message", data.trigger_message.trim());
  }

  const response = await withTimeoutFetch(`${API_BASE_URL}/api/v1/chat/upload-eml`, {
    method: "POST",
    body: formData,
  }, 300000);

  return (await response.json()) as ChatSendResponse;
}

export async function uploadChatFile(data: {
  file: File;
  conversation_id?: string | null;
  analysis_mode?: "quick" | "full";
  trigger_message?: string;
}): Promise<ChatSendResponse> {
  const formData = new FormData();
  formData.append("file", data.file);
  formData.append("analysis_mode", data.analysis_mode ?? "quick");
  if (data.conversation_id) {
    formData.append("conversation_id", data.conversation_id);
  }
  if (data.trigger_message && data.trigger_message.trim()) {
    formData.append("trigger_message", data.trigger_message.trim());
  }

  const response = await withTimeoutFetch(`${API_BASE_URL}/api/v1/chat/upload-file`, {
    method: "POST",
    body: formData,
  }, 300000);

  return (await response.json()) as ChatSendResponse;
}
