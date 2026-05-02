import React, { useRef, useEffect, useState } from 'react';

const SkillRing = ({ value, max = 100, label, color = '#00f2ea', size = 120, strokeWidth = 6 }) => {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const percentage = (value / max) * 100;
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <div className="relative inline-flex flex-col items-center justify-center">
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth={strokeWidth}
        />
        {mounted && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            style={{ transition: 'stroke-dashoffset 1.5s ease-out', filter: 'drop-shadow(0 0 10px currentColor)' }}
          />
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {mounted && (
          <span className="text-lg font-black text-white">
            {Math.round(percentage)}%
          </span>
        )}
        {label && (
          <span className="text-[9px] font-black text-white/40 uppercase tracking-widest">
            {label}
          </span>
        )}
      </div>
    </div>
  );
};

export default SkillRing;