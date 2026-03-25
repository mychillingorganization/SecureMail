import { useCallback, useMemo, useState } from "react";
import {
  createChatConversation,
  deleteChatConversation,
  fetchChatConversations,
  fetchChatMessages,
  sendChatMessage,
  uploadChatFile,
  uploadChatEml,
  type ChatConversation,
  type ChatMessage,
} from "../api/chat";

type ContextMode = "general" | "scan";

function createLocalMessage(
  conversationId: string,
  role: "user" | "assistant",
  content: string,
  status: string = "sent",
): ChatMessage {
  return {
    id: `local-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    conversation_id: conversationId,
    role,
    content,
    status,
    tool_name: null,
    tool_payload: null,
    created_at: new Date().toISOString(),
  };
}

export function useChat() {
  const [conversations, setConversations] = useState<ChatConversation[]>([]);
  const [messagesByConversation, setMessagesByConversation] = useState<Record<string, ChatMessage[]>>({});
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [isLoadingConversations, setIsLoadingConversations] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [isUploadingEml, setIsUploadingEml] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const activeMessages = useMemo(() => {
    if (!activeConversationId) return [];
    return messagesByConversation[activeConversationId] ?? [];
  }, [activeConversationId, messagesByConversation]);

  const loadConversations = useCallback(async () => {
    setIsLoadingConversations(true);
    try {
      const data = await fetchChatConversations(30);
      setConversations(data);
      if (!activeConversationId && data.length > 0) {
        setActiveConversationId(data[0].id);
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load conversations");
    } finally {
      setIsLoadingConversations(false);
    }
  }, [activeConversationId]);

  const loadMessages = useCallback(async (conversationId: string) => {
    try {
      const payload = await fetchChatMessages(conversationId, 200, 0);
      setMessagesByConversation((prev) => ({
        ...prev,
        [conversationId]: payload.messages,
      }));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load messages");
    }
  }, []);

  const startNewConversation = useCallback(async () => {
    try {
      const conversation = await createChatConversation();
      setConversations((prev) => {
        const withoutExisting = prev.filter((item) => item.id !== conversation.id);
        return [conversation, ...withoutExisting];
      });
      setMessagesByConversation((prev) => ({
        ...prev,
        [conversation.id]: prev[conversation.id] ?? [],
      }));
      setActiveConversationId(conversation.id);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create new conversation");
    }
  }, []);

  const removeConversation = useCallback(
    async (conversationId: string) => {
      try {
        await deleteChatConversation(conversationId);

        setConversations((prev) => {
          const next = prev.filter((item) => item.id !== conversationId);

          if (activeConversationId === conversationId) {
            setActiveConversationId(next.length > 0 ? next[0].id : null);
          }

          return next;
        });

        setMessagesByConversation((prev) => {
          const { [conversationId]: _, ...rest } = prev;
          return rest;
        });

        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to delete conversation");
      }
    },
    [activeConversationId],
  );

  const submitMessage = useCallback(
    async (message: string, contextMode: ContextMode = "general") => {
      const text = message.trim();
      if (!text || isSending) return;

      setIsSending(true);
      let conversationId = activeConversationId;
      let localUserId: string | null = null;
      let localAssistantId: string | null = null;
      try {
        if (!conversationId) {
          const created = await createChatConversation();
          conversationId = created.id;
          setConversations((prev) => {
            const withoutExisting = prev.filter((item) => item.id !== created.id);
            return [created, ...withoutExisting];
          });
          setMessagesByConversation((prev) => ({
            ...prev,
            [created.id]: prev[created.id] ?? [],
          }));
          setActiveConversationId(created.id);
        }

        if (!conversationId) {
          throw new Error("Conversation creation failed");
        }
        const cid = conversationId;

        const localUser = createLocalMessage(cid, "user", text, "sent");
        const localAssistant = createLocalMessage(cid, "assistant", "Analyzing your request...", "pending");
        localUserId = localUser.id;
        localAssistantId = localAssistant.id;

        setMessagesByConversation((prev) => ({
          ...prev,
          [cid]: [...(prev[cid] ?? []), localUser, localAssistant],
        }));

        const payload = await sendChatMessage({
          message: text,
          conversation_id: cid,
          context_mode: contextMode,
        });

        const returnedConversationId = payload.conversation.id;

        setConversations((prev) => {
          const withoutExisting = prev.filter((item) => item.id !== returnedConversationId);
          return [payload.conversation, ...withoutExisting];
        });

        setMessagesByConversation((prev) => ({
          ...prev,
          [returnedConversationId]: [
            ...(prev[returnedConversationId] ?? []).filter(
              (item) => item.id !== localUserId && item.id !== localAssistantId,
            ),
            payload.user_message,
            payload.assistant_message,
          ],
        }));

        setActiveConversationId(returnedConversationId);
        setError(null);
      } catch (err) {
        const detail = err instanceof Error ? err.message : "Failed to send message";
        setError(detail);

        if (conversationId && localAssistantId) {
          const cid = conversationId;
          setMessagesByConversation((prev) => ({
            ...prev,
            [cid]: (prev[cid] ?? []).map((item: ChatMessage) =>
              item.id === localAssistantId
                ? {
                    ...item,
                    status: "sent",
                    content: `I hit an error while processing your request: ${detail}`,
                  }
                : item,
            ),
          }));
        }
      } finally {
        setIsSending(false);
      }
    },
    [activeConversationId, isSending],
  );

  const submitAttachmentUpload = useCallback(
    async (
      file: File,
      scanMode: "rule" | "llm",
      userAcceptsDanger: boolean = false,
      triggerMessage?: string,
    ) => {
      if (isUploadingEml) return;

      setIsUploadingEml(true);
      let conversationId = activeConversationId;
      let localUserId: string | null = null;
      let localAssistantId: string | null = null;
      try {
        if (!conversationId) {
          const created = await createChatConversation();
          conversationId = created.id;
          setConversations((prev) => {
            const withoutExisting = prev.filter((item) => item.id !== created.id);
            return [created, ...withoutExisting];
          });
          setMessagesByConversation((prev) => ({
            ...prev,
            [created.id]: prev[created.id] ?? [],
          }));
          setActiveConversationId(created.id);
        }

        if (!conversationId) {
          throw new Error("Conversation creation failed");
        }
        const cid = conversationId;

        const localUser = createLocalMessage(
          cid,
          "user",
          triggerMessage?.trim() || `Uploaded file '${file.name}'`,
          "sent",
        );
        const localAssistant = createLocalMessage(
          cid,
          "assistant",
          `Analyzing ${file.name}...`,
          "pending",
        );
        localUserId = localUser.id;
        localAssistantId = localAssistant.id;

        setMessagesByConversation((prev) => ({
          ...prev,
          [cid]: [...(prev[cid] ?? []), localUser, localAssistant],
        }));

        const isEml = file.name.toLowerCase().endsWith(".eml");
        const payload = isEml
          ? await uploadChatEml({
              file,
              scan_mode: scanMode,
              user_accepts_danger: userAcceptsDanger,
              conversation_id: cid,
              trigger_message: triggerMessage,
            })
          : await uploadChatFile({
              file,
              analysis_mode: scanMode === "llm" ? "full" : "quick",
              conversation_id: cid,
              trigger_message: triggerMessage,
            });

        const returnedConversationId = payload.conversation.id;
        setConversations((prev) => {
          const withoutExisting = prev.filter((item) => item.id !== returnedConversationId);
          return [payload.conversation, ...withoutExisting];
        });

        setMessagesByConversation((prev) => ({
          ...prev,
          [returnedConversationId]: [
            ...(prev[returnedConversationId] ?? []).filter(
              (item) => item.id !== localUserId && item.id !== localAssistantId,
            ),
            payload.user_message,
            payload.assistant_message,
          ],
        }));

        setActiveConversationId(returnedConversationId);
        setError(null);
      } catch (err) {
        const detail = err instanceof Error ? err.message : "Failed to upload file";
        setError(detail);
        if (conversationId && localAssistantId) {
          const cid = conversationId;
          setMessagesByConversation((prev) => ({
            ...prev,
            [cid]: (prev[cid] ?? []).map((item: ChatMessage) =>
              item.id === localAssistantId
                ? {
                    ...item,
                    status: "sent",
                    content: `I hit an error while analyzing ${file.name}: ${detail}`,
                  }
                : item,
            ),
          }));
        }
      } finally {
        setIsUploadingEml(false);
      }
    },
    [activeConversationId, isUploadingEml],
  );

  return {
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
  };
}
