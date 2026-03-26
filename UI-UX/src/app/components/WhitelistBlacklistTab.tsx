import { useState, useEffect } from "react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { cn } from "./ui/utils";
import { useTheme } from "./ThemeContext";

type ListType = "url" | "file_hash";
type ActionType = "whitelist" | "blacklist";

interface WhitelistBlacklistItem {
  id: string;
  value: string;
  type: ListType;
  action: ActionType;
  created_at: string;
}

interface PaginatedResponse {
  total: number;
  skip: number;
  limit: number;
  items: WhitelistBlacklistItem[];
}

interface WhitelistBlacklistTabProps {
  isDark?: boolean;
  isFullPage?: boolean;
}

export function WhitelistBlacklistTab({ isDark: isDarkProp, isFullPage = false }: WhitelistBlacklistTabProps) {
  const { theme } = useTheme();
  const isDark = isDarkProp ?? theme === "dark";

  const ITEMS_PER_PAGE = 50;

  const [activeTab, setActiveTab] = useState<ListType>("url");
  const [actionTab, setActionTab] = useState<ActionType>("whitelist");
  const [newItem, setNewItem] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [items, setItems] = useState<WhitelistBlacklistItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [isSearching, setIsSearching] = useState(false);

  // Fetch items from backend with pagination
  const fetchItems = async (page: number) => {
    setLoading(true);
    setError(null);
    setIsSearching(false);
    try {
      const skip = (page - 1) * ITEMS_PER_PAGE;
      const response = await fetch(
        `/api/v1/list/${actionTab}?type=${activeTab}&skip=${skip}&limit=${ITEMS_PER_PAGE}`,
        { method: "GET" }
      );
      if (!response.ok) throw new Error(`Server error: ${response.status}`);
      
      const text = await response.text();
      console.log("Raw response:", text);
      
      const data = JSON.parse(text) as PaginatedResponse;
      setItems(data.items || []);
      setTotalItems(data.total || 0);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Failed to fetch items";
      console.error("Fetch error:", errMsg);
      setError(errMsg);
      setItems([]);
      setTotalItems(0);
    } finally {
      setLoading(false);
    }
  };

  // Search items across entire database
  const searchItems = async (query: string) => {
    if (!query.trim()) {
      // If search is cleared, go back to pagination
      setIsSearching(false);
      await fetchItems(1);
      return;
    }

    setLoading(true);
    setError(null);
    setIsSearching(true);
    try {
      const response = await fetch(
        `/api/v1/list/search?q=${encodeURIComponent(query)}&action=${actionTab}&type=${activeTab}`,
        { method: "GET" }
      );
      
      // Handle 400 errors - fall back to pagination
      if (response.status === 400) {
        console.warn("Search validation error, falling back to pagination");
        setIsSearching(false);
        await fetchItems(1);
        return;
      }
      
      if (!response.ok) throw new Error(`Server error: ${response.status}`);
      
      const text = await response.text();
      const data = JSON.parse(text);
      setItems(data.items || []);
      setTotalItems(data.total || 0);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Search failed";
      console.error("Search error:", errMsg);
      // Fall back to pagination on error
      setIsSearching(false);
      setError(null);
      await fetchItems(1);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setCurrentPage(1);
    setSearchQuery("");
    setIsSearching(false);
  }, [activeTab, actionTab]);

  useEffect(() => {
    void fetchItems(currentPage);
  }, [activeTab, actionTab, currentPage]);

  // Handle search query changes
  useEffect(() => {
    if (searchQuery.trim()) {
      void searchItems(searchQuery);
    } else if (isSearching) {
      // If search was active but query is now empty, reset to pagination
      setIsSearching(false);
      void fetchItems(1);
    }
  }, [searchQuery]);

  const handleAddItem = async () => {
    if (!newItem.trim()) return;

    setLoading(true);
    try {
      const formData = new FormData();
      formData.append("value", newItem.trim());
      formData.append("type", activeTab);
      formData.append("action", actionTab);

      const response = await fetch("/api/v1/list/add", {
        method: "POST",
        body: formData,
      });
      if (!response.ok) throw new Error(`Server error: ${response.status}`);
      
      const text = await response.text();
      console.log("Add response:", text);
      
      const data = JSON.parse(text);
      setNewItem("");
      // Reset to first page and refresh
      setCurrentPage(1);
      await fetchItems(1);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Failed to add item";
      console.error("Add error:", errMsg);
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveItem = async (id: string) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/v1/list/${id}`, { method: "DELETE" });
      if (!response.ok) throw new Error("Failed to remove item");
      // Refresh current page
      await fetchItems(currentPage);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove item");
    } finally {
      setLoading(false);
    }
  };

  const totalPages = Math.ceil(totalItems / ITEMS_PER_PAGE);

  return (
    <div className={cn("flex h-full w-full flex-col", isDark ? "bg-black/30" : "bg-white")}>
      <div className={cn("border-b px-4 py-3", isFullPage ? "py-4" : "")}>
        <h3 className={cn("font-semibold tracking-wide", isFullPage ? "text-lg" : "text-xs uppercase")}>{isFullPage ? "Whitelist & Blacklist Manager" : "Whitelist / Blacklist"}</h3>
        {isFullPage && <p className={cn("mt-1 text-sm", isDark ? "text-white/60" : "text-slate-600")}>Manage approved and blocked URLs and file hashes</p>}
      </div>

      {/* Type & Action Tabs */}
      <div className={cn("flex gap-1 border-b px-3 py-2", isFullPage ? "gap-2 px-4 py-3" : "")}>
        <div className="flex gap-1">
          {["url", "file_hash"].map((type) => (
            <button
              key={type}
              onClick={() => setActiveTab(type as ListType)}
              className={cn(
                "rounded px-2 py-1 font-medium transition-colors",
                isFullPage ? "px-3 py-1.5 text-sm" : "text-xs",
                activeTab === type
                  ? "bg-blue-600 text-white"
                  : isDark
                  ? "bg-white/5 hover:bg-white/10 text-white/60"
                  : "bg-slate-100 hover:bg-slate-200 text-slate-600"
              )}
            >
              {type === "url" ? "URLs" : "File Hashes"}
            </button>
          ))}
        </div>

        <div className={cn("ml-auto flex gap-1", isFullPage ? "gap-2" : "")}>
          {["whitelist", "blacklist"].map((action) => (
            <button
              key={action}
              onClick={() => setActionTab(action as ActionType)}
              className={cn(
                "rounded px-2 py-1 font-medium transition-colors",
                isFullPage ? "px-3 py-1.5 text-sm" : "text-xs",
                actionTab === action
                  ? "bg-blue-600 text-white"
                  : isDark
                  ? "bg-white/5 hover:bg-white/10 text-white/60"
                  : "bg-slate-100 hover:bg-slate-200 text-slate-600"
              )}
            >
              {isFullPage ? action.charAt(0).toUpperCase() + action.slice(1) : action.slice(0, 3).toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Search & Add */}
      <div className={cn("border-b px-3 py-2 space-y-2", isFullPage ? "px-4 py-3 space-y-2" : "space-y-1")}>
        {/* Search Bar */}
        <div className="relative">
          <Input
            type="text"
            placeholder={`Search ${activeTab === "url" ? "URLs" : "file hashes"}...`}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className={cn("w-full", isFullPage ? "h-9 text-sm" : "h-7 text-xs")}
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              className={cn(
                "absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded opacity-60 hover:opacity-100 transition-opacity",
                isDark ? "hover:bg-white/10" : "hover:bg-slate-100"
              )}
              aria-label="Clear search"
            >
              <span className="text-xs">✕</span>
            </button>
          )}
        </div>

        {/* Add Item */}
        <div className={cn("relative flex gap-2", isFullPage ? "gap-2" : "")}>
          <div className="flex-1">
            <Input
              type="text"
              placeholder={`Add new ${activeTab === "url" ? "URL" : "hash"}...`}
              value={newItem}
              onChange={(e) => setNewItem(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void handleAddItem();
              }}
              disabled={loading}
              className={cn("flex-1", isFullPage ? "h-9 text-sm" : "h-7 text-xs")}
            />
          </div>
          <Button
            onClick={() => void handleAddItem()}
            disabled={loading || !newItem.trim()}
            size={isFullPage ? "default" : "sm"}
            className={isFullPage ? "" : "h-7 px-2 text-xs"}
          >
            <span className={isFullPage ? "text-base" : "text-xs"}>+</span>
            {isFullPage && <span className="ml-1">Add</span>}
          </Button>
        </div>
      </div>

      {/* Items List */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {loading && items.length === 0 ? (
          <div className={cn("p-2 text-center", isFullPage ? "p-4" : "", isDark ? "text-white/40" : "text-slate-400")}>
            {isFullPage ? <p className="text-sm">{isSearching ? "Searching..." : "Loading items..."}</p> : <p className="text-xs">{isSearching ? "Searching..." : "Loading..."}</p>}
          </div>
        ) : error ? (
          <div className={cn("p-2 text-xs text-red-500", isFullPage ? "p-4 text-sm" : "")}>{error}</div>
        ) : items.length === 0 ? (
          <div className={cn("p-2 text-center", isFullPage ? "p-4" : "", isDark ? "text-white/40" : "text-slate-400")}>
            {isSearching ? (
              <>
                {isFullPage ? <p className="text-sm">No results matching "{searchQuery}"</p> : <p className="text-xs">No results</p>}
              </>
            ) : (
              <>
                {isFullPage ? <p className="text-sm">No items in {actionTab}</p> : <p className="text-xs">No items</p>}
              </>
            )}
          </div>
        ) : (
          <>
            <ul className={cn("space-y-0.5 px-2 py-1", isFullPage ? "space-y-1 px-4 py-2" : "")}>
              {items.map((item) => (
                <li
                  key={item.id}
                  className={cn(
                    "group flex items-center justify-between gap-2 rounded px-2 py-1",
                    isFullPage ? "px-3 py-2" : "",
                    isDark ? "hover:bg-white/10" : "hover:bg-slate-100"
                  )}
                >
                  <div className="flex-1 min-w-0">
                    <code className={cn("flex-1 truncate font-mono", isFullPage ? "text-sm" : "text-xs", isDark ? "text-white/60" : "text-slate-600")}>
                      {item.value}
                    </code>
                    {isFullPage && <p className={cn("text-xs mt-1", isDark ? "text-white/40" : "text-slate-500")}>
                      Added: {new Date(item.created_at).toLocaleDateString()}
                    </p>}
                  </div>
                  <button
                    onClick={() => void handleRemoveItem(item.id)}
                    disabled={loading}
                    className={cn(
                      "rounded opacity-0 transition-all group-hover:opacity-100 p-0.5",
                      isDark
                        ? "hover:bg-red-500/20 text-red-400"
                        : "hover:bg-red-100 text-red-600"
                    )}
                    aria-label="Delete"
                  >
                    <span className={isFullPage ? "text-sm" : "text-xs"}>Delete</span>
                  </button>
                </li>
              ))}
            </ul>

            {/* Pagination Controls - only show if not searching */}
            {!isSearching && totalPages > 1 && (
              <div className={cn("border-t flex items-center justify-between px-2 py-1", isFullPage ? "px-4 py-2" : "", isDark ? "bg-white/5" : "bg-slate-50")}>
                <div className={cn("text-xs", isDark ? "text-white/60" : "text-slate-600")}>
                  {isFullPage ? `Page ${currentPage} of ${totalPages} (${totalItems} total)` : `${currentPage}/${totalPages}`}
                </div>
                <div className="flex gap-1">
                  <button
                    onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                    disabled={currentPage === 1 || loading}
                    className={cn(
                      "rounded px-2 py-1 text-xs font-medium transition-colors",
                      currentPage === 1 || loading
                        ? isDark ? "bg-white/5 text-white/30" : "bg-slate-100 text-slate-400"
                        : isDark ? "bg-blue-600/40 hover:bg-blue-600/60 text-blue-300" : "bg-blue-100 hover:bg-blue-200 text-blue-700"
                    )}
                  >
                    {isFullPage ? "Previous" : "Prev"}
                  </button>
                  <button
                    onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                    disabled={currentPage === totalPages || loading}
                    className={cn(
                      "rounded px-2 py-1 text-xs font-medium transition-colors",
                      currentPage === totalPages || loading
                        ? isDark ? "bg-white/5 text-white/30" : "bg-slate-100 text-slate-400"
                        : isDark ? "bg-blue-600/40 hover:bg-blue-600/60 text-blue-300" : "bg-blue-100 hover:bg-blue-200 text-blue-700"
                    )}
                  >
                    {isFullPage ? "Next" : "Next"}
                  </button>
                </div>
              </div>
            )}

            {/* Search result count */}
            {isSearching && (
              <div className={cn("border-t px-2 py-1 text-xs", isFullPage ? "px-4 py-2" : "", isDark ? "bg-white/5 text-white/60" : "bg-slate-50 text-slate-600")}>
                Found {items.length} matching item{items.length !== 1 ? "s" : ""} in {actionTab}
              </div>
            )}
          </>
        )}
      </div>

      <div className={cn("border-t px-3 py-1", isFullPage ? "px-4 py-2" : "", isDark ? "text-white/30" : "text-slate-400")}>
        <p className={isFullPage ? "text-sm" : "text-[10px]"}>
          {totalItems} {activeTab === "url" ? "URL" : "hash"}
          {totalItems !== 1 ? "s" : ""} in {actionTab}
        </p>
      </div>
    </div>
  );
}
