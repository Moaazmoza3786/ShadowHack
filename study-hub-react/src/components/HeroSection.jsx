import React, { useState, useEffect, Suspense, lazy } from 'react';
import { Activity, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';
const ParticleField = lazy(() => import('./ParticleField'));
import GlitchText from './GlitchText';
import HealthPanel from './HealthPanel';

const HeroSection = ({ userName = "Operative" }) => {
  const [text, setText] = useState('');

  useEffect(() => {
    let index = 0;
    const fullText = 'TRANSCEND. EXPLOIT. SECURE.';
    const timer = setInterval(() => {
      if (index < fullText.length) {
        setText(fullText.slice(0, index + 1));
        index++;
      } else {
        clearInterval(timer);
      }
    }, 60);
    return () => clearInterval(timer);
  }, []);

  return (
    <section className="relative min-h-[70vh] flex items-center justify-center overflow-hidden py-20 px-6 rounded-[4rem] mb-10">
      <div className="absolute inset-0 -z-10 bg-dark-900">
        <Suspense fallback={null}>
          <ParticleField particleCount={40} connectionDistance={100} mouseRadius={150} showCode={true} className="opacity-25" />
        </Suspense>
        <div className="absolute top-[-15%] left-[-5%] w-[500px] h-[500px] bg-primary-500/10 rounded-full blur-[120px]" />
        <div className="absolute bottom-[-15%] right-[-5%] w-[500px] h-[500px] bg-accent-500/10 rounded-full blur-[120px]" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-16 items-center">
          <div className="lg:col-span-12 space-y-8">
            <div className="inline-flex items-center gap-3 px-4 py-2 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-xl hover:bg-white/10 hover:border-primary-500/20 transition-all cursor-default">
              <Activity size={16} className="text-primary-500" />
              <span className="text-[9px] font-black text-primary-500 uppercase tracking-[0.4em]">Uplink Established • Secure Channel</span>
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            </div>

            <div className="space-y-5">
              <GlitchText intensity="high" className="block">
                <h1 className="text-5xl md:text-6xl font-black text-white italic tracking-tighter uppercase leading-[0.85]">
                  <span className="block text-primary-500 mb-1">Shadow</span>
                  <span className="block underline decoration-accent-500/50 underline-offset-[10px]">Hack</span>
                </h1>
              </GlitchText>

              <div className="flex items-center gap-3 text-xl font-black text-white/40 italic uppercase tracking-widest h-10">
                <span className="text-primary-400">{text}</span>
                <span className="w-1.5 h-8 bg-primary-500 animate-pulse" />
              </div>
            </div>

            <p className="text-lg text-gray-400 max-w-xl font-medium leading-relaxed">
              Next-generation pentesting platform with real-time AI analysis and gamified learning experience.
            </p>

            <div className="flex flex-wrap gap-5">
              <button className="group relative px-8 py-4 bg-primary-500 text-dark-900 rounded-xl font-black uppercase italic tracking-tighter hover:scale-105 transition-all shadow-[0_15px_35px_rgba(0,242,234,0.3)] flex items-center gap-3 overflow-hidden">
                <div className="absolute inset-0 bg-white opacity-0 group-hover:opacity-20 transition-opacity" />
                <span>Start Mission</span>
                <ChevronRight className="group-hover:translate-x-1 transition-transform" size={18} />
              </button>
              <Link to="/tools" className="px-8 py-4 bg-transparent border-2 border-white/10 text-white rounded-xl font-black uppercase italic tracking-tighter hover:bg-white/5 hover:border-white/20 transition-all flex items-center gap-3">
                <Activity size={18} className="text-accent-500" />
                <span>Explore Tools</span>
              </Link>
            </div>
          </div>
        </div>
        <HealthPanel />
      </div>
    </section>
  );
};

export default HeroSection;
