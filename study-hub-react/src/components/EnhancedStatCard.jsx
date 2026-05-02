import React, { useMemo } from 'react';
import AnimatedCounter from './AnimatedCounter';
import SkillRing from './SkillRing';

const EnhancedStatCard = ({ label, value, icon: Icon, color, suffix = "", trend = null, progressValue = null }) => {
  const colorMap = {
    'bg-primary-500': { text: 'text-primary-500', light: 'bg-primary-500/5', border: 'border-primary-500/20', glow: 'shadow-[0_0_20px_rgba(0,242,234,0.25)]', hex: '#00f2ea' },
    'bg-green-500': { text: 'text-green-500', light: 'bg-green-500/5', border: 'border-green-500/20', glow: 'shadow-[0_0_20px_rgba(34,197,94,0.25)]', hex: '#22c55e' },
    'bg-red-500': { text: 'text-red-500', light: 'bg-red-500/5', border: 'border-red-500/20', glow: 'shadow-[0_0_20px_rgba(239,68,68,0.25)]', hex: '#ef4444' },
    'bg-yellow-500': { text: 'text-yellow-500', light: 'bg-yellow-500/5', border: 'border-yellow-500/20', glow: 'shadow-[0_0_20px_rgba(234,179,8,0.25)]', hex: '#eab308' },
    'bg-accent-500': { text: 'text-accent-500', light: 'bg-accent-500/5', border: 'border-accent-500/20', glow: 'shadow-[0_0_20px_rgba(255,0,85,0.25)]', hex: '#ff0055' },
  };

  const colors = colorMap[color] || colorMap['bg-primary-500'];

  const sparklineData = useMemo(() => {
    const points = [];
    let lastValue = 50;
    for (let i = 0; i < 10; i++) {
      lastValue += (Math.random() - 0.5) * 20;
      lastValue = Math.max(5, Math.min(95, lastValue));
      points.push(lastValue);
    }
    return points;
  }, []);

  const generateSparklinePath = () => {
    const width = 200;
    const height = 40;
    const points = sparklineData;
    const xStep = width / (points.length - 1);
    const maxVal = Math.max(...points);
    const minVal = Math.min(...points);
    const range = maxVal - minVal || 1;
    
    const pathParts = points.map((val, i) => {
      const x = i * xStep;
      const y = height - ((val - minVal) / range) * height * 0.8 - height * 0.1;
      return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
    });
    
    return pathParts.join(' ');
  };

  const trendValue = progressValue !== null ? progressValue : (trend ? trend.percentage + 50 : 65);

  return (
    <div className="relative group overflow-hidden bg-white/[0.03] backdrop-blur-3xl border border-white/5 rounded-[2rem] p-6 hover:border-white/20 hover:bg-white/[0.05] transition-all duration-700 cursor-pointer">
      <div className="absolute inset-0 bg-cyber-grid opacity-[0.03] group-hover:opacity-[0.06] transition-opacity duration-700" />
      <div className={`absolute top-0 right-0 w-32 h-32 blur-[60px] opacity-10 group-hover:opacity-20 transition-opacity duration-700 rounded-full ${color}`} />

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className="relative">
            <SkillRing value={trendValue} max={100} size={40} strokeWidth={3} color={colors.hex} showPercentage={false} className="absolute inset-0 opacity-30" />
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center border border-white/5 bg-dark-950/50 relative group-hover:border-white/20 transition-all ${colors.glow}`}>
              <Icon size={16} className={`${colors.text} drop-shadow-[0_0_8px_currentColor]`} />
            </div>
          </div>
          {trend && (
            <div className={`px-3 py-1 rounded-full text-[9px] font-black tracking-widest uppercase flex items-center gap-2 border bg-white/5 ${trend.isPositive ? 'text-green-500 border-green-500/20' : 'text-red-500 border-red-500/20'}`}>
              <div className={`w-1 h-1 rounded-full animate-pulse ${trend.isPositive ? 'bg-green-500' : 'bg-red-500'}`} />
              {trend.isPositive ? '+' : ''}{trend.percentage}%
            </div>
          )}
        </div>

        <div className="space-y-1 mb-3">
          <h4 className="text-[10px] font-black text-white/30 uppercase tracking-[0.3em] italic">{label}</h4>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black text-white tracking-tighter uppercase italic leading-[0.8] drop-shadow-sm">
              <AnimatedCounter value={value} duration={1500} />
            </span>
            {suffix && <span className="text-[10px] font-black text-white/30 tracking-widest uppercase italic">{suffix}</span>}
          </div>
        </div>

        <div className="h-10 mt-3 relative overflow-hidden rounded-xl">
          <svg className="w-full h-full" preserveAspectRatio="none" viewBox="0 0 200 40">
            <defs>
              <linearGradient id={`gradient-${label}`} x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor={colors.hex} stopOpacity="0.3" />
                <stop offset="100%" stopColor={colors.hex} stopOpacity="0" />
              </linearGradient>
            </defs>
            <path d={`M 0 40 ${generateSparklinePath()} L 200 40 Z`} fill={`url(#gradient-${label})`} />
            <path d={generateSparklinePath()} fill="none" stroke={colors.hex} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>

        <div className="pt-3 border-t border-white/5 mt-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[8px] font-black text-white/20 uppercase tracking-[0.2em]">Sync</span>
            <span className="text-[8px] font-black text-white/40 uppercase tracking-[0.1em]">Optimal</span>
          </div>
          <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${color} opacity-80`} style={{ width: `${trendValue}%` }} />
          </div>
        </div>
      </div>

      <div className="absolute bottom-4 right-6 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-all translate-x-4 group-hover:translate-x-0 duration-500 pointer-events-none">
        <div className="w-1 h-1 rounded-full bg-white/20" />
        <div className="w-1 h-1 rounded-full bg-white/40" />
        <div className="w-1 h-1 rounded-full bg-white/60" />
      </div>
    </div>
  );
};

export default EnhancedStatCard;