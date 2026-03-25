import { Check, X, Clock } from "lucide-react";
import { useState } from "react";
import { useTheme } from "./ThemeContext";
import { ScanDetail } from "./ScanDetail";
import type { ScanHistoryItem } from "../api/scanHistory";

const StatusIcon = ({ status, isDark }: { status: string, isDark: boolean }) => {
  if (status === "PASS") return <Check className={`h-4 w-4 ${isDark ? 'text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.8)]' : 'text-emerald-600'}`} />;
  if (status === "DANGER") return <X className={`h-4 w-4 ${isDark ? 'text-rose-500 drop-shadow-[0_0_8px_rgba(244,63,94,0.8)]' : 'text-rose-600'}`} />;
  return <Clock className={`h-4 w-4 ${isDark ? 'text-amber-400 drop-shadow-[0_0_8px_rgba(251,191,36,0.8)]' : 'text-amber-600'}`} />;
};

interface ActivityTableProps {
  scanHistory: ScanHistoryItem[];
}

export function ActivityTable({ scanHistory = [] }: ActivityTableProps) {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const [selectedScan, setSelectedScan] = useState<ScanHistoryItem | null>(null);

  // Sort by timestamp, newest first
  const sortedHistory = [...scanHistory].sort((a, b) => 
    new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHour / 24);

    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHour < 24) return `${diffHour}h ago`;
    if (diffDay < 7) return `${diffDay}d ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className={`flex h-full w-full flex-col overflow-hidden rounded-xl border ${isDark ? 'border-white/5 bg-black/40' : 'border-slate-200 bg-white/80'} p-6 backdrop-blur-xl`}>
      <div className="mb-4">
        <h2 className={`text-lg font-semibold tracking-wide ${isDark ? 'text-white/90 drop-shadow-[0_0_8px_rgba(255,255,255,0.2)]' : 'text-slate-800'}`}>
          Scan History
        </h2>
        <p className={`text-xs font-medium ${isDark ? 'text-white/40' : 'text-slate-500'}`}>All scanned emails and their security status</p>
      </div>

      <div className="flex-1 overflow-auto">
        <table className={`w-full text-left text-sm ${isDark ? 'text-white/70' : 'text-slate-600'}`}>
          <thead className={`sticky top-0 ${isDark ? 'bg-[#08080c]/80 text-white/40' : 'bg-slate-50/90 text-slate-500'} text-xs uppercase backdrop-blur-md`}>
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
            {sortedHistory.length === 0 ? (
              <tr>
                <td colSpan={6} className={`px-4 py-8 text-center ${isDark ? 'text-white/40' : 'text-slate-500'}`}>
                  No scans yet. Start by uploading an email in the Check Email section.
                </td>
              </tr>
            ) : (
              sortedHistory.map((row) => (
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
                    {formatTime(row.timestamp)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Scan Detail Modal */}
      <ScanDetail scan={selectedScan} onClose={() => setSelectedScan(null)} />
    </div>
  );
}
