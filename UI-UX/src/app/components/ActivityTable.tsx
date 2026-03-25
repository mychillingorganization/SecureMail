import { Check, X, Clock } from "lucide-react";
import { useTheme } from "./ThemeContext";

const activities = [
  {
    id: "LOG-0192",
    status: "success",
    type: "Inbound Payload",
    source: "mail.enterprise.internal",
    size: "4.2 MB",
    time: "2m ago",
  },
  {
    id: "LOG-0191",
    status: "error",
    type: "Malware Signature",
    source: "external-unknown.xyz",
    size: "89 KB",
    time: "5m ago",
  },
  {
    id: "LOG-0190",
    status: "pending",
    type: "Queue Backup",
    source: "eu-west-node-1",
    size: "128 MB",
    time: "12m ago",
  },
  {
    id: "LOG-0189",
    status: "success",
    type: "Policy Update",
    source: "admin.alpha",
    size: "12 KB",
    time: "15m ago",
  },
  {
    id: "LOG-0188",
    status: "success",
    type: "DLP Scan",
    source: "sales.finance.corp",
    size: "1.1 MB",
    time: "22m ago",
  },
];

const StatusIcon = ({ status, isDark }: { status: string, isDark: boolean }) => {
  if (status === "success") return <Check className={`h-4 w-4 ${isDark ? 'text-emerald-400 drop-shadow-[0_0_8px_rgba(52,211,153,0.8)]' : 'text-emerald-600'}`} />;
  if (status === "error") return <X className={`h-4 w-4 ${isDark ? 'text-rose-500 drop-shadow-[0_0_8px_rgba(244,63,94,0.8)]' : 'text-rose-600'}`} />;
  return <Clock className={`h-4 w-4 ${isDark ? 'text-amber-400 drop-shadow-[0_0_8px_rgba(251,191,36,0.8)]' : 'text-amber-600'}`} />;
};

export function ActivityTable() {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  return (
    <div className={`flex h-full w-full flex-col overflow-hidden rounded-xl border ${isDark ? 'border-white/5 bg-black/40' : 'border-slate-200 bg-white/80'} p-6 backdrop-blur-xl`}>
      <div className="mb-4">
        <h2 className={`text-lg font-semibold tracking-wide ${isDark ? 'text-white/90 drop-shadow-[0_0_8px_rgba(255,255,255,0.2)]' : 'text-slate-800'}`}>
          Recent Activity
        </h2>
        <p className={`text-xs font-medium ${isDark ? 'text-white/40' : 'text-slate-500'}`}>Real-time gateway security logs</p>
      </div>

      <div className="flex-1 overflow-auto">
        <table className={`w-full text-left text-sm ${isDark ? 'text-white/70' : 'text-slate-600'}`}>
          <thead className={`sticky top-0 ${isDark ? 'bg-[#08080c]/80 text-white/40' : 'bg-slate-50/90 text-slate-500'} text-xs uppercase backdrop-blur-md`}>
            <tr>
              <th className="px-4 py-3 font-semibold tracking-wider rounded-tl-lg">Status</th>
              <th className="px-4 py-3 font-semibold tracking-wider">Event ID</th>
              <th className="px-4 py-3 font-semibold tracking-wider">Type</th>
              <th className="px-4 py-3 font-semibold tracking-wider">Source</th>
              <th className="px-4 py-3 font-semibold tracking-wider">Size</th>
              <th className="px-4 py-3 font-semibold tracking-wider rounded-tr-lg">Time</th>
            </tr>
          </thead>
          <tbody className={`divide-y ${isDark ? 'divide-white/5' : 'divide-slate-100'}`}>
            {activities.map((row) => (
              <tr
                key={row.id}
                className={`group transition-colors ${isDark ? 'border-white/5 hover:bg-white/5' : 'border-slate-100 hover:bg-slate-50'}`}
              >
                <td className="px-4 py-3">
                  <div className={`flex h-7 w-7 items-center justify-center rounded-md border shadow-inner ${isDark ? 'bg-white/5 border-white/5' : 'bg-white border-slate-200'}`}>
                    <StatusIcon status={row.status} isDark={isDark} />
                  </div>
                </td>
                <td className={`px-4 py-3 font-medium tracking-wide ${isDark ? 'text-white/90' : 'text-slate-800'}`}>{row.id}</td>
                <td className={`px-4 py-3 font-medium ${isDark ? 'text-white/80' : 'text-slate-700'}`}>{row.type}</td>
                <td className={`px-4 py-3 ${isDark ? 'text-white/50' : 'text-slate-500'}`}>{row.source}</td>
                <td className={`px-4 py-3 font-medium ${isDark ? 'text-white/70' : 'text-slate-600'}`}>{row.size}</td>
                <td className={`px-4 py-3 ${isDark ? 'text-white/50' : 'text-slate-500'}`}>{row.time}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
