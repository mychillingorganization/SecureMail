import { Bell, Menu, User, Sun, Moon, Calendar, ChevronDown } from "lucide-react";
import { useTheme } from "./ThemeContext";

export function Header() {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-white/5 dark:border-white/5 bg-white/95 dark:bg-black/70 px-6 transition-colors">
      <div className="flex items-center gap-4">
        <button className="rounded-md p-2 text-slate-500 dark:text-white/50 transition-colors hover:bg-slate-100 dark:hover:bg-white/10 hover:text-slate-900 dark:hover:text-white lg:hidden">
          <Menu className="h-5 w-5" />
        </button>
        <div className="relative flex items-center group">
          <div className="flex items-center gap-2 rounded-full border border-blue-500/30 dark:border-blue-500/40 bg-white dark:bg-white/5 px-4 py-1.5 text-sm text-slate-800 dark:text-blue-100 shadow-sm transition-colors hover:border-blue-500/60 dark:hover:border-blue-400/60 cursor-pointer">
            <Calendar className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            <span className="font-medium">Last 24 Hours</span>
            <ChevronDown className="h-4 w-4 text-slate-400 dark:text-blue-300/70 ml-1" />
          </div>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <button 
          onClick={toggleTheme}
          className="rounded-full p-2 text-slate-500 dark:text-white/50 transition-colors hover:bg-slate-100 dark:hover:bg-white/10 hover:text-amber-500 dark:hover:text-amber-300"
          title="Toggle Theme"
        >
          {theme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
        </button>
        <div className="relative">
          <button className="rounded-full p-2 text-slate-500 dark:text-white/50 transition-colors hover:bg-slate-100 dark:hover:bg-white/10 hover:text-slate-900 dark:hover:text-white">
            <Bell className="h-5 w-5" />
          </button>
          <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-orange-500 shadow-sm" />
        </div>
        <div className="h-6 w-px bg-slate-200 dark:bg-white/10" />
        <button className="flex items-center gap-2 rounded-full p-1 pl-3 transition-colors hover:bg-slate-100 dark:hover:bg-white/5">
          <div className="flex flex-col text-right">
            <span className="text-sm font-medium text-slate-900 dark:text-white/90">Admin Alpha</span>
            <span className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-white/40">Level 5 Auth</span>
          </div>
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-blue-500/20 to-purple-500/20 border border-blue-500/30 dark:border-white/10">
            <User className="h-5 w-5 text-blue-600 dark:text-blue-400" />
          </div>
        </button>
      </div>
    </header>
  );
}
