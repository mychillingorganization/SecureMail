import React from 'react';

export function SecureMailLogo({ className = "", isDark = true }: { className?: string, isDark?: boolean }) {
  return (
    <div className={`flex flex-col items-center justify-center gap-3 ${className}`}>
      <div className="relative flex items-center justify-center w-full">
        {/* Subtle background glow for the envelope */}
        <div className="absolute inset-0 rounded-2xl bg-blue-500/10 blur-[20px]" />
        
        {/* Drop shadow on the SVG helps with the neon outline look */}
        <svg 
          viewBox="0 0 120 72" 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg" 
          className="relative w-full h-auto drop-shadow-[0_0_8px_rgba(59,130,246,0.6)]"
        >
          <defs>
            {/* Deep navy to slate gray linear gradient for the envelope body */}
            <linearGradient id="envelope-gradient" x1="0" y1="0" x2="120" y2="72" gradientUnits="userSpaceOnUse">
              <stop stopColor="#0f172a" />
              <stop offset="1" stopColor="#1e293b" />
            </linearGradient>

            {/* Mask to cut out the keyhole from the envelope */}
            <mask id="keyhole-mask">
              <rect width="120" height="72" fill="white" rx="8" />
              {/* 
                Keyhole shape: 
                Top circle (center 60,31; radius 8), 
                Neck comes down, widens out to a base 
              */}
              <path 
                d="M60 23C55 23 51 27 51 32C51 35.5 53 38.5 56 40L53 52H67L64 40C67 38.5 69 35.5 69 32C69 27 65 23 60 23Z" 
                fill="black" 
              />
            </mask>
          </defs>

          {/* Envelope Body */}
          <rect 
            width="120" 
            height="72" 
            rx="8" 
            fill="url(#envelope-gradient)" 
            mask="url(#keyhole-mask)" 
          />
          
          {/* Envelope Borders - Double stroke for neon flow effect */}
          <rect 
            x="1" 
            y="1" 
            width="118" 
            height="70" 
            rx="7" 
            stroke="#3b82f6" 
            strokeWidth="2" 
            strokeOpacity="0.8"
            mask="url(#keyhole-mask)" 
          />
          <rect 
            x="1" 
            y="1" 
            width="118" 
            height="70" 
            rx="7" 
            stroke="#93c5fd" 
            strokeWidth="0.5" 
            strokeOpacity="0.5"
            mask="url(#keyhole-mask)" 
          />
          
          {/* Envelope Flap Lines */}
          <path 
            d="M2 2L60 38L118 2" 
            stroke="#3b82f6" 
            strokeWidth="1.5" 
            strokeOpacity="0.5" 
            mask="url(#keyhole-mask)" 
          />
          
          <path 
            d="M2 70L40 46" 
            stroke="#3b82f6" 
            strokeWidth="1.5" 
            strokeOpacity="0.3" 
            mask="url(#keyhole-mask)" 
          />
          <path 
            d="M118 70L80 46" 
            stroke="#3b82f6" 
            strokeWidth="1.5" 
            strokeOpacity="0.3" 
            mask="url(#keyhole-mask)" 
          />

          {/* Keyhole Border */}
          <path 
            d="M60 23C55 23 51 27 51 32C51 35.5 53 38.5 56 40L53 52H67L64 40C67 38.5 69 35.5 69 32C69 27 65 23 60 23Z" 
            stroke="#3b82f6" 
            strokeWidth="2.5" 
            fill="none" 
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          {/* Inner bright core for keyhole border */}
          <path 
            d="M60 23C55 23 51 27 51 32C51 35.5 53 38.5 56 40L53 52H67L64 40C67 38.5 69 35.5 69 32C69 27 65 23 60 23Z" 
            stroke="#93c5fd" 
            strokeWidth="1" 
            fill="none" 
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>

      <div className={`font-sans text-[13px] sm:text-[14px] font-bold tracking-[0.25em] select-none ${isDark ? 'text-white drop-shadow-[0_0_10px_rgba(59,130,246,0.8)]' : 'text-slate-800 drop-shadow-[0_0_8px_rgba(59,130,246,0.4)]'}`}>
        SECUREMAIL
      </div>
    </div>
  );
}
