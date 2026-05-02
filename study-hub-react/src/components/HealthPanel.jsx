import React, { useEffect, useState } from 'react';

// Small health status panel for Frontend/Backend/Ollama
const HealthPanel = () => {
  const [status, setStatus] = useState(null);
  const [frontendStatus] = useState('loaded');

  useEffect(() => {
    let mounted = true;
    fetch('/api/health/status')
      .then((r) => r.json())
      .then((data) => {
        if (mounted) setStatus(data);
      })
      .catch(() => {
        if (mounted) setStatus({ backend: 'unhealthy', ollama: 'unreachable', database: 'unknown' });
      });
    return () => { mounted = false; };
  }, []);

  if (!status) {
    return (
      <div className="health-panel p-3 rounded border border-white/20 text-xs text-white/70">Loading health…</div>
    );
  }

  const badge = (label, ok) => (
    <span className={"px-2 py-1 rounded-full text-white text-xs" + (ok ? ' bg-green-600' : ' bg-yellow-500')}>{label}</span>
  );

  return (
    <div className="health-panel mt-6 p-4 rounded border border-white/20 bg-white/5 text-xs text-white/80">
      <div className="grid grid-cols-3 gap-4 items-center">
        <div>
          Backend: {status.backend || 'unknown'}
          {status.backend === 'healthy' ? <>{' '}{badge('OK', true)}</> : null}
          <div className="mt-1 text-[10px] text-white/40">
            DB: {status.database || 'unknown'}
          </div>
        </div>
        <div>
          Ollama: {status.ollama || 'unknown'}
          {status.ollama === 'healthy' ? <>{' '}{badge('OK', true)}</> : null}
        </div>
        <div>
          Frontend: {frontendStatus}
          {frontendStatus === 'loaded' ? <>{' '}{badge('OK', true)}</> : null}
        </div>
      </div>
    </div>
  );
};

export default HealthPanel;
