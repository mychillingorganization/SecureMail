import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { useTheme } from "./ThemeContext";
import { cn } from "./ui/utils";
import { WhitelistBlacklistTab } from "./WhitelistBlacklistTab";

export function WhitelistBlacklistPage() {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  return (
    <div className={cn("relative flex h-screen w-full overflow-hidden", isDark ? "bg-[#030308] text-white" : "bg-slate-50 text-slate-900")}>
      <Sidebar />

      <div className="relative z-10 flex flex-1 flex-col overflow-hidden">
        <Header />

        <main className="flex-1 min-h-0 overflow-hidden p-6 md:p-8">
          <div className="mx-auto h-full min-h-0 max-w-7xl">
            <section className={cn("flex h-full min-h-0 flex-col rounded-xl border", isDark ? "border-white/10 bg-black/30" : "border-slate-200 bg-white")}>
              <WhitelistBlacklistTab isDark={isDark} isFullPage={true} />
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}
