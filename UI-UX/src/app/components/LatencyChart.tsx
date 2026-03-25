import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useTheme } from "./ThemeContext";

const data = [
  { day: "Mon", emails: 24000 },
  { day: "Tue", emails: 35000 },
  { day: "Wed", emails: 48000 },
  { day: "Thu", emails: 32000 },
  { day: "Fri", emails: 65000 },
  { day: "Sat", emails: 85000 },
  { day: "Sun", emails: 42000 },
];

export function LatencyChart() {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  return (
    <div className={`relative flex h-full min-h-[300px] w-full flex-col overflow-hidden rounded-xl border ${isDark ? 'border-white/5 bg-black/40' : 'border-slate-200 bg-white/80'} p-6 backdrop-blur-xl`}>
      <div className="mb-6 flex items-center justify-between z-10">
        <div>
          <h2 className={`text-lg font-semibold tracking-wide ${isDark ? 'text-white/90 drop-shadow-[0_0_8px_rgba(255,255,255,0.2)]' : 'text-slate-800'}`}>
            Processing Latency
          </h2>
          <p className={`text-xs font-medium ${isDark ? 'text-white/40' : 'text-slate-500'}`}>Real-time ms delay across network nodes</p>
        </div>
        <div className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-medium cursor-pointer transition-all ${isDark ? 'border-blue-500/30 bg-blue-500/10 text-blue-100 shadow-[0_0_15px_rgba(59,130,246,0.2)] hover:border-blue-400/50 hover:shadow-[0_0_20px_rgba(59,130,246,0.4)]' : 'border-blue-200 bg-blue-50 text-blue-700 shadow-sm hover:border-blue-300'}`}>
          <div className={`h-2 w-2 rounded-full ${isDark ? 'bg-blue-400 shadow-[0_0_8px_rgba(59,130,246,0.8)]' : 'bg-blue-500'} animate-pulse`} />
          <span>Real-time delay</span>
          <svg className={`h-4 w-4 ml-1 opacity-70 ${isDark ? 'text-blue-300' : 'text-blue-600'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>

      <div className="flex-1 w-full min-w-0 min-h-0 z-10 relative">
        <div className="absolute inset-0">
          <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart data={data} margin={{ top: 10, right: 10, left: 10, bottom: 0 }}>
            <defs key="defs">
              <linearGradient id="colorLatency" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={isDark ? "#3b82f6" : "#2563eb"} stopOpacity={0.3} />
                <stop offset="95%" stopColor={isDark ? "#3b82f6" : "#2563eb"} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid key="grid" strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.05)"} vertical={false} />
            <XAxis
              key="xaxis"
              dataKey="day"
              stroke={isDark ? "rgba(255,255,255,0.2)" : "rgba(0,0,0,0.2)"}
              tick={{ fill: isDark ? "rgba(255,255,255,0.4)" : "rgba(0,0,0,0.5)", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              key="yaxis"
              stroke={isDark ? "rgba(255,255,255,0.2)" : "rgba(0,0,0,0.2)"}
              tick={{ fill: isDark ? "rgba(255,255,255,0.4)" : "rgba(0,0,0,0.5)", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              tickFormatter={(value) => `${value / 1000}k`}
            />
            <Tooltip
              key="tooltip"
              contentStyle={{
                backgroundColor: isDark ? "rgba(10,10,15,0.9)" : "rgba(255,255,255,0.9)",
                borderColor: isDark ? "rgba(255,255,255,0.1)" : "rgba(0,0,0,0.1)",
                borderRadius: "8px",
                backdropFilter: "blur(12px)",
                boxShadow: isDark ? "0 0 20px rgba(59,130,246,0.2)" : "0 4px 6px -1px rgba(0,0,0,0.1)",
              }}
              itemStyle={{ color: isDark ? "#fff" : "#0f172a", fontSize: "12px", fontWeight: "bold" }}
              labelStyle={{ color: isDark ? "rgba(255,255,255,0.5)" : "rgba(0,0,0,0.5)", fontSize: "10px" }}
              cursor={{ stroke: isDark ? "rgba(59,130,246,0.3)" : "rgba(37,99,235,0.3)", strokeWidth: 2, strokeDasharray: "4 4" }}
              formatter={(value: number) => [`${value.toLocaleString()} Emails`, 'Volume']}
            />
            <Area
              key="area"
              type="monotone"
              dataKey="emails"
              stroke={isDark ? "#3b82f6" : "#2563eb"}
              strokeWidth={3}
              fillOpacity={1}
              fill="url(#colorLatency)"
              activeDot={{
                r: 6,
                fill: isDark ? "#3b82f6" : "#2563eb",
                stroke: isDark ? "#fff" : "#fff",
                strokeWidth: 2,
                style: { filter: isDark ? "drop-shadow(0px 0px 8px rgba(59,130,246,1))" : "drop-shadow(0px 0px 4px rgba(37,99,235,0.5))" },
              }}
              dot={{
                r: 4,
                fill: isDark ? "rgba(10,10,15,1)" : "rgba(255,255,255,1)",
                stroke: isDark ? "#3b82f6" : "#2563eb",
                strokeWidth: 2,
              }}
            />
          </AreaChart>
        </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
