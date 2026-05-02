import React, { useState } from 'react';

const GlitchText = ({ children, intensity = 'medium', className = '' }) => {
  const [isGlitching, setIsGlitching] = useState(false);

  const intensityMap = {
    low: { translate: 1, duration: 0.1, textShadow: '2px 0 0 var(--c1), -2px 0 0 var(--c2)' },
    medium: { translate: 2, duration: 0.08, textShadow: '3px 0 0 var(--c1), -3px 0 0 var(--c2)' },
    high: { translate: 4, duration: 0.05, textShadow: '4px 0 0 var(--c1), -4px 0 0 var(--c2), 0 0 20px var(--c1)' }
  };

  const config = intensityMap[intensity] || intensityMap.medium;

  return (
    <span
      className={`relative inline-block ${className}`}
      onMouseEnter={() => setIsGlitching(true)}
      onMouseLeave={() => setIsGlitching(false)}
      style={{
        '--c1': '#00f2ea',
        '--c2': '#ff0055'
      }}
    >
      {isGlitching && (
        <>
          <span
            style={{
              position: 'absolute',
              left: `-${config.translate}px`,
              top: `-${config.translate}px`,
              color: '#00f2ea',
              opacity: 0.7,
              mixBlendMode: 'screen',
              animation: `${config.duration}s infinite`
            }}
          >
            {children}
          </span>
          <span
            style={{
              position: 'absolute',
              left: `${config.translate}px`,
              top: `-${config.translate}px`,
              color: '#ff0055',
              opacity: 0.7,
              mixBlendMode: 'screen',
              animation: `${config.duration}s infinite 0.04s`
            }}
          >
            {children}
          </span>
        </>
      )}
      {children}
    </span>
  );
};

export default GlitchText;