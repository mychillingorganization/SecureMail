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

const API_BASE_URL = (import.meta as { env?: Record<string, string | undefined> }).env?.VITE_API_BASE_URL || "http://localhost:8080";

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
