import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "motion/react";

interface Point {
  id: number;
  x: number;
  y: number;
}

export function CursorEffect() {
  const [trail, setTrail] = useState<Point[]>([]);

  useEffect(() => {
    let animationFrameId: number;
    let currentId = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const newPoint = { id: currentId++, x: e.clientX, y: e.clientY };
      setTrail((prev) => {
        const newTrail = [...prev, newPoint];
        if (newTrail.length > 20) {
          return newTrail.slice(newTrail.length - 20);
        }
        return newTrail;
      });
    };

    window.addEventListener("mousemove", handleMouseMove);

    // Cleanup old trail points periodically to prevent them from sticking
    // if mouse stops moving
    const cleanupInterval = setInterval(() => {
      setTrail((prev) => {
        if (prev.length > 0) {
          return prev.slice(1);
        }
        return prev;
      });
    }, 50);

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      clearInterval(cleanupInterval);
    };
  }, []);

  return (
    <div className="pointer-events-none fixed inset-0 z-50 overflow-hidden">
      <AnimatePresence>
        {trail.map((point, index) => (
          <motion.div
            key={point.id}
            initial={{ opacity: 0.8, scale: 1 }}
            animate={{ opacity: 0, scale: 0.1 }}
            exit={{ opacity: 0, scale: 0 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
            className="absolute rounded-full mix-blend-screen"
            style={{
              left: point.x - 8,
              top: point.y - 8,
              width: 16,
              height: 16,
              background: "radial-gradient(circle, rgba(100,200,255,0.8) 0%, rgba(50,50,255,0) 70%)",
              boxShadow: "0 0 10px rgba(100,200,255,0.5)",
            }}
          />
        ))}
      </AnimatePresence>
    </div>
  );
}
