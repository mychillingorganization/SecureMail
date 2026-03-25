import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { KPICard } from "./KPICard";
import { ActivityTable } from "./ActivityTable";
import { CursorEffect } from "./CursorEffect";
import { ParticleBackground } from "./ParticleBackground";
import { Zap, Mail, OctagonAlert } from "lucide-react";
import { useTheme } from "./ThemeContext";
import { useScanHistory } from "../hooks/useScanHistory";

export function Dashboard() {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const { history } = useScanHistory(100, undefined, false);

  // Calculate metrics from scan history
  const totalScanned = history.length;
  const passedScans = history.filter(s => s.final_status === "PASS").length;
  const issuesFound = history.reduce((sum, s) => sum + (s.issue_count || 0), 0);
  const errorRate = totalScanned > 0 ? ((totalScanned - passedScans) / totalScanned * 100).toFixed(2) : "0.00";

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: `
        @keyframes border-spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .animate-border-spin {
          animation: border-spin 4s linear infinite;
        }
        
        .gravity-grid-bg {
          background-size: 60px 60px;
          background-image: 
            linear-gradient(to right, ${isDark ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.05)'} 1px, transparent 1px),
            linear-gradient(to bottom, ${isDark ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.05)'} 1px, transparent 1px);
        }
        
        /* Simulates an abstract 3D gravity curve by masking out the edges */
        .gravity-mask {
          mask-image: radial-gradient(circle at center, rgba(0,0,0,1) 40%, rgba(0,0,0,0.2) 100%);
          -webkit-mask-image: radial-gradient(circle at center, rgba(0,0,0,1) 40%, rgba(0,0,0,0.2) 100%);
        }
      `}} />
      
      <div className={`relative flex h-screen w-full ${isDark ? 'bg-[#030308] text-white' : 'bg-slate-50 text-slate-900'} overflow-hidden font-sans selection:bg-blue-500/30 transition-colors duration-500`}>
        
        {/* Background Layers */}
        <div className={`absolute inset-0 ${isDark ? 'bg-gradient-to-br from-[#0a0a1a] via-[#05050f] to-black opacity-90' : 'bg-gradient-to-br from-slate-100 via-slate-50 to-white opacity-90'} z-0`} />
        <div className={`absolute inset-0 gravity-grid-bg gravity-mask z-0 ${isDark ? 'mix-blend-screen' : 'mix-blend-multiply'}`} />
        {isDark && <ParticleBackground />}
        
        {/* Interactive Layer */}
        {isDark && <CursorEffect />}

        {/* Layout */}
        <Sidebar />

        <div className="relative flex flex-1 flex-col overflow-hidden z-10">
          <Header />

          <main className="flex-1 overflow-auto p-6 md:p-8">
            <div className="mx-auto max-w-7xl space-y-6">
              
              {/* Header Title */}
              <div className="mb-8 flex items-end justify-between">
                <div>
                  <h1 className={`text-3xl font-bold tracking-tight ${isDark ? 'text-white/95 drop-shadow-[0_0_15px_rgba(255,255,255,0.3)]' : 'text-slate-800'}`}>
                    Email Security Monitor
                  </h1>
                  <p className={`mt-1 text-sm ${isDark ? 'text-white/40' : 'text-slate-500'}`}>
                    Live email scanning analytics and threat detection
                  </p>
                </div>
                <div className={`flex h-10 items-center justify-center rounded-lg border px-4 text-xs font-semibold shadow-inner backdrop-blur-md ${isDark ? 'border-white/5 bg-white/5 text-white/50' : 'border-slate-200 bg-white/50 text-slate-500'}`}>
                  Last updated: 1s ago
                </div>
              </div>

              {/* KPI Cards */}
              <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
                <KPICard
                  title="Total Emails Scanned"
                  value={totalScanned.toString()}
                  subtext={`${passedScans} passed security check`}
                  trend="up"
                  glowColor="blue"
                  icon={<Zap size={16} />}
                />
                <KPICard
                  title="Issues Detected"
                  value={issuesFound.toString()}
                  subtext={`${((issuesFound / Math.max(totalScanned, 1)) * 100).toFixed(1)}% of emails`}
                  trend={issuesFound > 0 ? "up" : "down"}
                  glowColor="gold"
                  icon={<Mail size={16} />}
                />
                <KPICard
                  title="Threat Detection Rate"
                  value={`${errorRate}%`}
                  subtext={`${totalScanned - passedScans} threats found`}
                  trend="down"
                  glowColor="orange"
                  icon={<OctagonAlert size={16} />}
                />
              </div>

              {/* Main Data Section */}
              <div className="flex flex-col gap-6">
                <div className="w-full min-h-[400px] min-w-0">
                  <ActivityTable scanHistory={history} />
                </div>
              </div>

            </div>
          </main>
        </div>
      </div>
    </>
  );
}
