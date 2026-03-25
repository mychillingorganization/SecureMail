import { useEffect, useMemo, useState } from "react";
import { useTheme } from "./ThemeContext";
import { ScanDetail } from "./ScanDetail";
import type { ScanHistoryItem } from "../api/scanHistory";

const StatusIcon = ({ status, isDark }: { status: string, isDark: boolean }) => {
  if (status === "PASS") return <span className={`${isDark ? "text-emerald-400" : "text-emerald-600"}`}>OK</span>;
  if (status === "DANGER") return <span className={`${isDark ? "text-rose-500" : "text-rose-600"}`}>X</span>;
  return <span className={`${isDark ? "text-amber-400" : "text-amber-600"}`}>...</span>;
};

interface ActivityTableProps {
  scanHistory: ScanHistoryItem[];
  currentPage: number;
  totalPages: number;
  totalItems: number;
  isLoading: boolean;
  onPageChange: (page: number) => void;
  searchTerm: string;
  onSearchChange: (value: string) => void;
}

function formatRelativeTime(timestamp: string, now: number): string {
  const date = new Date(timestamp);
  const diffMs = now - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHour < 24) return `${diffHour}h ago`;
  if (diffDay < 7) return `${diffDay}d ago`;
  return date.toLocaleDateString();
}

export function ActivityTable({
  scanHistory = [],
  currentPage,
  totalPages,
  totalItems,
  isLoading,
  onPageChange,
  searchTerm,
  onSearchChange,
}: ActivityTableProps) {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const [selectedScan, setSelectedScan] = useState<ScanHistoryItem | null>(null);
  const [searchInput, setSearchInput] = useState(searchTerm);

  useEffect(() => {
    setSearchInput(searchTerm);
  }, [searchTerm]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (searchInput !== searchTerm) {
        onSearchChange(searchInput);
      }
    }, 300);
    return () => window.clearTimeout(timer);
  }, [searchInput, searchTerm, onSearchChange]);

  // Backend already returns sorted history for current page.
  const now = useMemo(() => Date.now(), [scanHistory.length]);
  const displayRows = useMemo(
    () => scanHistory.map((row) => ({ ...row, relativeTime: formatRelativeTime(row.timestamp, now) })),
    [scanHistory, now],
  );

  return (
    <div className={`flex h-full w-full flex-col overflow-hidden rounded-xl border ${isDark ? 'border-white/5 bg-black/30' : 'border-slate-200 bg-white'} p-6`}>
      <div className="mb-4">
        <h2 className={`text-lg font-semibold tracking-wide ${isDark ? 'text-white/90' : 'text-slate-800'}`}>
          Scan History
        </h2>
        <p className={`text-xs font-medium ${isDark ? 'text-white/40' : 'text-slate-500'}`}>All scanned emails and their security status</p>
        <div className="mt-3 relative max-w-md">
          <input
            type="text"
            value={searchInput}
            onChange={(event) => setSearchInput(event.target.value)}
            placeholder="Search by file name, sender, or receiver"
            className={`w-full rounded-md border px-3 py-2 text-sm outline-none transition-colors ${
              isDark
                ? 'border-white/10 bg-white/5 text-white placeholder:text-white/35 focus:border-blue-400/60'
                : 'border-slate-200 bg-white text-slate-800 placeholder:text-slate-400 focus:border-blue-400'
            }`}
          />
        </div>
      </div>

      <div className="flex-1 overflow-auto overscroll-contain [contain:content]">
        <table className={`w-full text-left text-sm ${isDark ? 'text-white/70' : 'text-slate-600'}`}>
          <thead className={`${isDark ? 'bg-[#08080c] text-white/40' : 'bg-slate-50 text-slate-500'} text-xs uppercase`}>
            <tr>
              <th className="px-4 py-3 font-semibold tracking-wider rounded-tl-lg">Status</th>
              <th className="px-4 py-3 font-semibold tracking-wider">File Name</th>
              <th className="px-4 py-3 font-semibold tracking-wider">Mode</th>
              <th className="px-4 py-3 font-semibold tracking-wider">Issues</th>
              <th className="px-4 py-3 font-semibold tracking-wider">Duration</th>
              <th className="px-4 py-3 font-semibold tracking-wider rounded-tr-lg">Time</th>
            </tr>
          </thead>
          <tbody className={`divide-y ${isDark ? 'divide-white/5' : 'divide-slate-100'}`}>
            {isLoading ? (
              <tr>
                <td colSpan={6} className={`px-4 py-8 text-center ${isDark ? 'text-white/40' : 'text-slate-500'}`}>
                  Loading scan history...
                </td>
              </tr>
            ) : displayRows.length === 0 ? (
              <tr>
                <td colSpan={6} className={`px-4 py-8 text-center ${isDark ? 'text-white/40' : 'text-slate-500'}`}>
                  No scans yet. Start by uploading an email in the Check Email section.
                </td>
              </tr>
            ) : (
              displayRows.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => setSelectedScan(row)}
                  className={`group transition-colors cursor-pointer ${isDark ? 'border-white/5 hover:bg-white/5' : 'border-slate-100 hover:bg-slate-50'}`}
                >
                  <td className="px-4 py-3">
                    <div className={`flex h-7 w-7 items-center justify-center rounded-md border shadow-inner ${isDark ? 'bg-white/5 border-white/5' : 'bg-white border-slate-200'}`}>
                      <StatusIcon status={row.final_status} isDark={isDark} />
                    </div>
                  </td>
                  <td className={`px-4 py-3 font-medium tracking-wide ${isDark ? 'text-white/90' : 'text-slate-800'}`}>
                    {row.file_name}
                  </td>
                  <td className={`px-4 py-3 font-medium ${isDark ? 'text-white/80' : 'text-slate-700'}`}>
                    <span className={`rounded px-2 py-0.5 text-xs font-semibold ${
                      row.scan_mode === 'llm'
                        ? isDark ? 'bg-purple-500/20 text-purple-300' : 'bg-purple-100 text-purple-700'
                        : isDark ? 'bg-blue-500/20 text-blue-300' : 'bg-blue-100 text-blue-700'
                    }`}>
                      {row.scan_mode === 'llm' ? 'LLM' : 'Rule'}
                    </span>
                  </td>
                  <td className={`px-4 py-3 ${isDark ? 'text-white/50' : 'text-slate-500'}`}>
                    {row.issue_count}
                  </td>
                  <td className={`px-4 py-3 font-medium ${isDark ? 'text-white/70' : 'text-slate-600'}`}>
                    {row.duration_ms ? `${(row.duration_ms / 1000).toFixed(1)}s` : '-'}
                  </td>
                  <td className={`px-4 py-3 ${isDark ? 'text-white/50' : 'text-slate-500'}`}>
                    {row.relativeTime}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="mt-3 flex items-center justify-between">
        <p className={`text-xs ${isDark ? 'text-white/40' : 'text-slate-500'}`}>
          Showing page {currentPage} of {totalPages} ({totalItems} total scans).
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => onPageChange(Math.max(1, currentPage - 1))}
            disabled={currentPage === 1 || isLoading}
            className={`rounded px-3 py-1 text-xs font-medium ${
              currentPage === 1 || isLoading
                ? isDark ? 'bg-white/5 text-white/30' : 'bg-slate-100 text-slate-400'
                : isDark ? 'bg-blue-600/30 text-blue-300 hover:bg-blue-600/40' : 'bg-blue-100 text-blue-700 hover:bg-blue-200'
            }`}
          >
            Previous
          </button>
          <button
            type="button"
            onClick={() => onPageChange(Math.min(totalPages, currentPage + 1))}
            disabled={currentPage >= totalPages || isLoading}
            className={`rounded px-3 py-1 text-xs font-medium ${
              currentPage >= totalPages || isLoading
                ? isDark ? 'bg-white/5 text-white/30' : 'bg-slate-100 text-slate-400'
                : isDark ? 'bg-blue-600/30 text-blue-300 hover:bg-blue-600/40' : 'bg-blue-100 text-blue-700 hover:bg-blue-200'
            }`}
          >
            Next
          </button>
        </div>
      </div>

      {/* Scan Detail Modal */}
      <ScanDetail scan={selectedScan} onClose={() => setSelectedScan(null)} />
    </div>
  );
}
