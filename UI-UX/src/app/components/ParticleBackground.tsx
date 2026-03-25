import { useEffect, useMemo, useState } from "react";

interface Particle {
  id: string;
  x: number;
  y: number;
  size: number;
  duration: number;
  delay: number;
  opacity: number;
  drift: number;
}

export function ParticleBackground() {
  const [enabled, setEnabled] = useState(false);
  const [particleCount, setParticleCount] = useState(20);

  useEffect(() => {
    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => {
      const canAnimate = !mediaQuery.matches;
      setEnabled(canAnimate);
      setParticleCount(window.innerWidth < 1024 ? 10 : 20);
    };

    update();
    mediaQuery.addEventListener("change", update);
    window.addEventListener("resize", update);

    return () => {
      mediaQuery.removeEventListener("change", update);
      window.removeEventListener("resize", update);
    };
  }, []);

  const particles = useMemo(() => {
    return Array.from({ length: particleCount }).map((_, i) => ({
      id: `particle-${i}-${Math.random().toString(36).substring(2, 9)}`,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 2 + 1,
      duration: Math.random() * 8 + 14,
      delay: Math.random() * 6,
      opacity: Math.random() * 0.35 + 0.08,
      drift: Math.random() * 18 - 9,
    }));
  }, [particleCount]);

  if (!enabled) return null;

  return (
    <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden mix-blend-screen">
      <style>{`
        @keyframes particle-float {
          0% { transform: translate3d(0, 0, 0); }
          50% { transform: translate3d(var(--drift), -14px, 0); }
          100% { transform: translate3d(calc(var(--drift) * -1), -26px, 0); }
        }
      `}</style>
      {particles.map((p) => (
        <span
          key={p.id}
          className="absolute rounded-full bg-blue-300"
          style={{
            left: `${p.x}%`,
            top: `${p.y}%`,
            width: p.size,
            height: p.size,
            opacity: p.opacity,
            boxShadow: `0 0 ${p.size * 2}px rgba(147,197,253,0.35)`,
            animationName: "particle-float",
            animationDuration: `${p.duration}s`,
            animationDelay: `${p.delay}s`,
            animationTimingFunction: "linear",
            animationIterationCount: "infinite",
            // CSS custom property to avoid recalculating keyframes.
            ["--drift" as string]: `${p.drift}px`,
          }}
        />
      ))}
    </div>
  );
}
