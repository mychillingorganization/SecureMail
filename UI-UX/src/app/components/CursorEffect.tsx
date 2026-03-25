import { useEffect, useRef, useState } from "react";

interface Point {
  id: number;
  x: number;
  y: number;
}

export function CursorEffect() {
  const [trail, setTrail] = useState<Point[]>([]);
  const idRef = useRef(0);
  const rafRef = useRef<number | null>(null);
  const latestPointRef = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      latestPointRef.current = { x: e.clientX, y: e.clientY };

      if (rafRef.current !== null) return;

      rafRef.current = window.requestAnimationFrame(() => {
        const latest = latestPointRef.current;
        if (!latest) {
          rafRef.current = null;
          return;
        }

        const newPoint = { id: idRef.current++, x: latest.x, y: latest.y };
        setTrail((prev) => {
          const next = [...prev, newPoint];
          return next.length > 8 ? next.slice(next.length - 8) : next;
        });

        rafRef.current = null;
      });
    };

    window.addEventListener("mousemove", handleMouseMove);

    // Fade out quickly while idle to avoid unnecessary DOM updates.
    const cleanupInterval = window.setInterval(() => {
      setTrail((prev) => {
        return prev.length > 0 ? prev.slice(1) : prev;
      });
    }, 120);

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      clearInterval(cleanupInterval);
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
      }
    };
  }, []);

  return (
    <div className="pointer-events-none fixed inset-0 z-50 hidden overflow-hidden lg:block">
      {trail.map((point, index) => {
        const factor = (index + 1) / trail.length;
        return (
          <div
            key={point.id}
            className="absolute rounded-full mix-blend-screen transition-all duration-300"
            style={{
              left: point.x - 6,
              top: point.y - 6,
              width: 12,
              height: 12,
              opacity: 0.08 + factor * 0.35,
              transform: `scale(${0.35 + factor * 0.65})`,
              background: "radial-gradient(circle, rgba(100,200,255,0.8) 0%, rgba(50,50,255,0) 70%)",
              boxShadow: "0 0 8px rgba(100,200,255,0.35)",
            }}
          />
        );
      })}
    </div>
  );
}
