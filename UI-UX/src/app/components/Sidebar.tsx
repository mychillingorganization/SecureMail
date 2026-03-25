import {
  LayoutDashboard,
  Mail,
} from "lucide-react";
import { useLocation, useNavigate } from "react-router";
import { useTheme } from "./ThemeContext";
import { SecureMailLogo } from "./SecureMailLogo";

export function Sidebar() {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const location = useLocation();
  const navigate = useNavigate();

  const navItems = [
    { icon: LayoutDashboard, label: "Monitor", path: "/" },
  ];

  return (
    <aside className={`hidden lg:flex w-64 flex-col border-r z-20 h-full transition-colors ${isDark ? 'border-white/5 bg-black/40' : 'border-slate-200 bg-white shadow-sm'}`}>
      <div className={`flex flex-col items-center justify-center border-b py-8 ${isDark ? 'border-white/5' : 'border-slate-200'}`}>
        <SecureMailLogo isDark={isDark} className="w-36" />
      </div>

      <nav className="flex-1 space-y-3 p-4">
        <div className={`mb-4 mt-2 px-2 text-[10px] font-semibold uppercase tracking-widest ${isDark ? 'text-white/30' : 'text-slate-400'}`}>
          Core Modules
        </div>
        {navItems.map((item, idx) => (
          <button
            key={idx}
            onClick={() => navigate(item.path)}
            className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
              location.pathname === item.path
                ? isDark 
                  ? "bg-white/5 text-blue-400 font-medium border border-white/5 shadow-[inset_2px_0_0_0_#3b82f6]"
                  : "bg-blue-50 text-blue-600 font-medium border-l-2 border-blue-500 shadow-sm"
                : isDark
                  ? "text-white/40 hover:bg-white/5 hover:text-white/80"
                  : "text-slate-500 hover:bg-slate-50 hover:text-slate-800"
            }`}
          >
            <item.icon
              className={`h-4 w-4 ${
                location.pathname === item.path
                  ? isDark ? "text-blue-400" : "text-blue-600"
                  : isDark ? "text-white/30 group-hover:text-white/60" : "text-slate-400 group-hover:text-slate-600"
              }`}
            />
            {item.label}
          </button>
        ))}

        <button
          onClick={() => navigate("/scanner")}
          className={`mt-2 flex w-full items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-bold transition-all shadow-md active:scale-95 ${
          isDark 
            ? "bg-blue-600 text-white hover:bg-blue-500 hover:shadow-[0_0_20px_rgba(59,130,246,0.4)] border border-blue-400/20" 
            : "bg-blue-600 text-white hover:bg-blue-700 hover:shadow-lg border border-transparent"
        }`}
        >
          <Mail className="h-4 w-4" />
          Check Email
        </button>
      </nav>

      <div className={`mt-auto border-t p-4 ${isDark ? 'border-white/5' : 'border-slate-200'}`}>
        <div className={`rounded-lg p-4 text-center border ${isDark ? 'bg-white/5 border-white/5' : 'bg-slate-50 border-slate-200'}`}>
          <div className={`mb-2 text-xs font-medium ${isDark ? 'text-white/50' : 'text-slate-500'}`}>System Status</div>
          <div className="flex items-center justify-center gap-2">
            <div className={`h-2 w-2 rounded-full ${isDark ? 'bg-emerald-400 shadow-sm' : 'bg-emerald-500 shadow-sm'}`} />
            <span className={`text-xs font-semibold ${isDark ? 'text-emerald-400' : 'text-emerald-600'}`}>All Nodes Active</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
