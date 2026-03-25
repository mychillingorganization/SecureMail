import { ReactNode } from "react";
import { useTheme } from "./ThemeContext";

interface KPICardProps {
  title: string;
  value: string;
  subtext: string;
  icon: ReactNode;
  glowColor: "blue" | "gold" | "orange" | "teal";
  trend: "up" | "down" | "neutral";
}

export function KPICard({ title, value, subtext, icon, glowColor, trend }: KPICardProps) {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  const colorMap = {
    blue: {
      from: "from-blue-500/0",
      via: "via-blue-500",
      to: "to-blue-500/0",
      text: isDark ? "text-blue-400" : "text-blue-600",
      shadow: "shadow-[0_0_20px_rgba(59,130,246,0.6)]",
      bgInner: isDark ? "bg-blue-500/10" : "bg-blue-100",
      glowVar: "#3b82f6",
      lightBorder: "border-blue-200",
    },
    gold: {
      from: "from-amber-400/0",
      via: "via-amber-400",
      to: "to-amber-400/0",
      text: isDark ? "text-amber-400" : "text-amber-600",
      shadow: "shadow-[0_0_20px_rgba(251,191,36,0.6)]",
      bgInner: isDark ? "bg-amber-400/10" : "bg-amber-100",
      glowVar: "#fbbf24",
      lightBorder: "border-amber-200",
    },
    teal: {
      from: "from-teal-400/0",
      via: "via-teal-400",
      to: "to-teal-400/0",
      text: isDark ? "text-teal-400" : "text-teal-600",
      shadow: "shadow-[0_0_20px_rgba(45,212,191,0.6)]",
      bgInner: isDark ? "bg-teal-400/10" : "bg-teal-100",
      glowVar: "#2dd4bf",
      lightBorder: "border-teal-200",
    },
    orange: {
      from: "from-orange-500/0",
      via: "via-orange-500",
      to: "to-orange-500/0",
      text: isDark ? "text-orange-500" : "text-orange-600",
      shadow: "shadow-[0_0_20px_rgba(249,115,22,0.6)]",
      bgInner: isDark ? "bg-orange-500/10" : "bg-orange-100",
      glowVar: "#f97316",
      lightBorder: "border-orange-200",
    },
  };

  const currentColors = colorMap[glowColor];

  return (
    <div className={`group relative h-32 w-full overflow-hidden rounded-xl ${isDark ? 'bg-black/40 p-[1px]' : 'bg-white shadow-sm p-0 border border-slate-200'} backdrop-blur-xl transition-all duration-300 hover:scale-[1.02]`}>
      {/* Animated glowing border flow (Dark mode only) */}
      {isDark && (
        <div
          className="absolute -inset-full animate-border-spin"
          style={{
            background: `conic-gradient(from 0deg, transparent 0%, transparent 80%, ${currentColors.glowVar} 100%)`,
          }}
        />
      )}
      
      {/* Card Content */}
      <div className={`relative flex h-full w-full flex-col justify-between rounded-xl ${isDark ? 'bg-[#08080c]/90 border border-white/5 p-4' : `bg-white p-4 border-l-4 ${currentColors.lightBorder}`} backdrop-blur-2xl z-10`}>
        <div className="flex items-center justify-between">
          <span className={`text-xs font-semibold uppercase tracking-wider ${isDark ? 'text-white/40' : 'text-slate-500'}`}>
            {title}
          </span>
          <div
            className={`flex h-8 w-8 items-center justify-center rounded-lg ${currentColors.bgInner} ${isDark ? currentColors.shadow : ''} transition-shadow duration-300 ${isDark ? `group-hover:shadow-[0_0_30px_${currentColors.glowVar}]` : ''}`}
          >
            <div className={currentColors.text}>{icon}</div>
          </div>
        </div>

        <div>
          <div className={`text-2xl font-bold tracking-tight ${isDark ? 'text-white drop-shadow-[0_0_10px_rgba(255,255,255,0.4)]' : 'text-slate-800'}`}>
            {value}
          </div>
          <div className={`mt-1 flex items-center text-[10px] font-medium ${isDark ? 'text-white/50' : 'text-slate-500'}`}>
            <span
              className={
                trend === "up"
                  ? isDark ? "text-emerald-400" : "text-emerald-600"
                  : trend === "down"
                  ? isDark ? "text-rose-400" : "text-rose-600"
                  : isDark ? "text-white/40" : "text-slate-400"
              }
            >
              {trend === "up" ? "↑" : trend === "down" ? "↓" : "−"}{" "}
            </span>
            <span className="ml-1">{subtext}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
