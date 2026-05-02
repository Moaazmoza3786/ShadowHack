import React, { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, ExternalLink, Globe2, Info, RefreshCw, ShieldAlert } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import Globe from 'react-globe.gl';

const MONITORED_COUNTRIES = [
  { code: 'US', label: 'United States', lat: 38.9072, lng: -77.0369 },
  { code: 'GB', label: 'United Kingdom', lat: 51.5074, lng: -0.1278 },
  { code: 'DE', label: 'Germany', lat: 52.52, lng: 13.405 },
  { code: 'AE', label: 'UAE', lat: 25.2048, lng: 55.2708 },
  { code: 'IN', label: 'India', lat: 28.6139, lng: 77.209 },
  { code: 'SG', label: 'Singapore', lat: 1.3521, lng: 103.8198 },
  { code: 'JP', label: 'Japan', lat: 35.6762, lng: 139.6503 },
  { code: 'AU', label: 'Australia', lat: -35.2809, lng: 149.13 },
  { code: 'FR', label: 'France', lat: 48.8566, lng: 2.3522 },
  { code: 'CA', label: 'Canada', lat: 45.4215, lng: -75.6972 },
  { code: 'BR', label: 'Brazil', lat: -15.7975, lng: -47.8919 },
  { code: 'RU', label: 'Russia', lat: 55.7558, lng: 37.6173 },
  { code: 'CN', label: 'China', lat: 39.9042, lng: 116.4074 },
  { code: 'KR', label: 'South Korea', lat: 37.5665, lng: 126.978 },
  { code: 'IR', label: 'Iran', lat: 35.6892, lng: 51.389 },
  { code: 'KP', label: 'North Korea', lat: 39.0392, lng: 125.7625 },
  { code: 'UA', label: 'Ukraine', lat: 50.4501, lng: 30.5234 },
  { code: 'PL', label: 'Poland', lat: 52.2297, lng: 21.0122 },
  { code: 'IT', label: 'Italy', lat: 41.9028, lng: 12.4964 },
  { code: 'ES', label: 'Spain', lat: 40.4168, lng: -3.7038 },
  { code: 'NL', label: 'Netherlands', lat: 52.3676, lng: 4.9041 },
  { code: 'SE', label: 'Sweden', lat: 59.3293, lng: 18.0686 },
  { code: 'CH', label: 'Switzerland', lat: 46.9481, lng: 7.4474 },
  { code: 'SA', label: 'Saudi Arabia', lat: 24.7136, lng: 46.6753 },
  { code: 'TR', label: 'Turkey', lat: 39.9334, lng: 32.8597 },
  { code: 'PK', label: 'Pakistan', lat: 33.6844, lng: 73.0479 },
  { code: 'VN', label: 'Vietnam', lat: 21.0285, lng: 105.8542 },
  { code: 'ID', label: 'Indonesia', lat: -6.2088, lng: 106.8456 },
  { code: 'MY', label: 'Malaysia', lat: 3.139, lng: 101.6869 },
  { code: 'TH', label: 'Thailand', lat: 13.7563, lng: 100.5018 },
  { code: 'PH', label: 'Philippines', lat: 14.5995, lng: 120.9842 },
  { code: 'ZA', label: 'South Africa', lat: -25.7479, lng: 28.2293 },
  { code: 'EG', label: 'Egypt', lat: 30.0444, lng: 31.2357 },
  { code: 'NG', label: 'Nigeria', lat: 9.0765, lng: 7.3986 },
  { code: 'MX', label: 'Mexico', lat: 19.4326, lng: -99.1332 },
  { code: 'AR', label: 'Argentina', lat: -34.6037, lng: -58.3816 },
  { code: 'CL', label: 'Chile', lat: -33.4489, lng: -70.6693 },
  { code: 'CO', label: 'Colombia', lat: 4.711, lng: -74.0721 },
];

const GlobalThreatGlobe = () => {
  const { apiUrl } = useAppContext();
  const [selectedCountry, setSelectedCountry] = useState(MONITORED_COUNTRIES[0]);
  const [countryInfo, setCountryInfo] = useState(null);
  const [intelItems, setIntelItems] = useState([]);
  const [relatedCves, setRelatedCves] = useState([]);
  const [kevMatches, setKevMatches] = useState([]);
  const [lastIntelUpdatedAt, setLastIntelUpdatedAt] = useState(null);
  const [globeRingsData, setGlobeRingsData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [refreshTick, setRefreshTick] = useState(0);
  const [showControls, setShowControls] = useState(false);
  const [countryScores, setCountryScores] = useState({});

  const globeRef = useRef(null);
  const globeWrapRef = useRef(null);
  const [globeSize, setGlobeSize] = useState({ w: 720, h: 520 });

  useEffect(() => {
    const el = globeWrapRef.current;
    if (!el) return;

    const ro = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      const w = Math.max(320, Math.floor(entry.contentRect.width));
      const h = Math.max(360, Math.floor(Math.min(620, w * 0.72)));
      setGlobeSize({ w, h });
    });

    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (!globeRef.current) return;
    try {
      const controls = globeRef.current.controls();
      if (controls) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.4;
      }
    } catch {
      // ignore
    }
  }, [globeSize.w, globeSize.h]);

  useEffect(() => {
    let isCancelled = false;

    const loadCountry = async () => {
      try {
        const res = await fetch(`https://restcountries.com/v3.1/alpha/${selectedCountry.code}`);
        const data = await res.json();
        if (!isCancelled && Array.isArray(data) && data[0]) {
          setCountryInfo(data[0]);
        }
      } catch {
        if (!isCancelled) setCountryInfo(null);
      }
    };

    loadCountry();
    return () => {
      isCancelled = true;
    };
  }, [selectedCountry]);

  useEffect(() => {
    let isCancelled = false;

    const loadIntelForCountry = async () => {
      setLoading(true);
      try {
        const localizedRes = await fetch(`${apiUrl}/intel/news?country=${selectedCountry.code}`);
        const localizedData = await localizedRes.json();

        if (!isCancelled && localizedData?.success && localizedData?.items?.length > 0) {
          setIntelItems(localizedData.items.slice(0, 6));
          const cves = (localizedData.cves || []).slice(0, 6);
          setRelatedCves(cves);
          setLastIntelUpdatedAt(localizedData.last_updated || null);

          // Enrich CVEs with CISA KEV when possible (trusted source).
          if (cves.length > 0) {
            try {
              const kevRes = await fetch(`${apiUrl}/intel/kev?cves=${encodeURIComponent(cves.join(','))}&limit=6`);
              const kevData = await kevRes.json();
              if (!isCancelled && kevData?.success) {
                setKevMatches(kevData.items || []);
              }
            } catch {
              if (!isCancelled) setKevMatches([]);
            }
          } else {
            setKevMatches([]);
          }

          // Update a derived "activity score" for the selected country (based on real feed volume).
          setCountryScores((prev) => {
            const score = Math.min(100, 20 + localizedData.items.slice(0, 20).length * 6 + cves.length * 10);
            return { ...prev, [selectedCountry.code]: score };
          });
          return;
        }

        const genericRes = await fetch(`${apiUrl}/intel/news`);
        const genericData = await genericRes.json();
        if (!isCancelled && genericData?.success) {
          const fallbackItems = (genericData.items || []).slice(0, 6);
          setIntelItems(fallbackItems);
          const cves = (genericData.cves || []).slice(0, 6);
          setRelatedCves(cves);
          setKevMatches([]);
          setLastIntelUpdatedAt(genericData.last_updated || null);
          setCountryScores((prev) => {
            const score = Math.min(100, 15 + fallbackItems.length * 5 + cves.length * 8);
            return { ...prev, [selectedCountry.code]: score };
          });
        }
      } catch {
        if (!isCancelled) {
          setIntelItems([]);
          setRelatedCves([]);
          setKevMatches([]);
          setLastIntelUpdatedAt(null);
        }
      } finally {
        if (!isCancelled) setLoading(false);
      }
    };

    loadIntelForCountry();
    // تحديث البيانات كل 30 ثانية بدلاً من دقيقة
    const interval = setInterval(() => setRefreshTick((v) => v + 1), 30000);
    return () => {
      isCancelled = true;
      clearInterval(interval);
    };
  }, [apiUrl, selectedCountry.code, refreshTick]);

  const countryMeta = useMemo(() => {
    if (!countryInfo) return null;
    return {
      name: countryInfo?.name?.common || selectedCountry.label,
      official: countryInfo?.name?.official || '-',
      flag: countryInfo?.flag || '',
      population: countryInfo?.population ? countryInfo.population.toLocaleString() : '-',
      region: countryInfo?.region || '-',
      subregion: countryInfo?.subregion || '-',
      capital: countryInfo?.capital?.[0] || '-',
      timezone: countryInfo?.timezones?.[0] || '-',
    };
  }, [countryInfo, selectedCountry.label]);

  const activityScore = useMemo(() => {
    const fromCache = countryScores[selectedCountry.code];
    if (typeof fromCache === 'number') return fromCache;
    return Math.min(100, 15 + intelItems.length * 6 + relatedCves.length * 10);
  }, [countryScores, selectedCountry.code, intelItems.length, relatedCves.length]);

  const riskLevel = useMemo(() => {
    if (activityScore >= 80) return 'critical';
    if (activityScore >= 65) return 'high';
    if (activityScore >= 45) return 'elevated';
    return 'moderate';
  }, [activityScore]);

  const globePoints = useMemo(
    () =>
      MONITORED_COUNTRIES.map((country) => ({
        lat: country.lat,
        lng: country.lng,
        size: selectedCountry.code === country.code ? 0.5 : 0.28,
        color: selectedCountry.code === country.code ? '#ef4444' : '#94a3b8',
        label: `${country.label} (${country.code})`,
      })),
    [selectedCountry.code]
  );

  useEffect(() => {
    setGlobeRingsData((prev) => [
      ...prev,
      {
        lat: selectedCountry.lat,
        lng: selectedCountry.lng,
        maxR: 8,
        propagationSpeed: 1.8,
        repeatPeriod: 900,
      },
    ]);
  }, [selectedCountry]);

  return (
    <section className="p-8 rounded-[2.5rem] bg-white/[0.02] border border-white/5 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-primary-500/[0.04] via-transparent to-accent-500/[0.04] pointer-events-none" />

      <div className="relative z-10 flex items-center justify-between gap-4 mb-8 flex-wrap">
        <div className="flex items-center gap-3">
          <Globe2 className="text-primary-500" size={20} />
          <div>
            <h2 className="text-2xl font-black text-white italic uppercase tracking-tight">Global Threat Map</h2>
            <p className="text-[10px] font-black text-white/40 uppercase tracking-[0.25em] mt-1">
              Live country intel + trusted feeds (auto)
            </p>
            <p className="text-[10px] font-black text-white/30 uppercase tracking-[0.2em] mt-1">
              {lastIntelUpdatedAt ? `Last sync: ${new Date(lastIntelUpdatedAt).toLocaleString()}` : 'Last sync: —'} • Auto refresh: 30s
            </p>
          </div>
        </div>

        <button
          onClick={() => setRefreshTick((v) => v + 1)}
          className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-white/70 hover:text-white hover:bg-white/10 transition-colors flex items-center gap-2 text-xs font-black uppercase tracking-wider"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 relative z-10">
        <div className="lg:col-span-2">
          <div ref={globeWrapRef} className="relative mx-auto w-full max-w-[820px] rounded-3xl border border-white/10 bg-dark-950/80 overflow-hidden shadow-[0_0_80px_rgba(0,242,234,0.14)]">
            <div className="absolute inset-0 bg-cyber-grid opacity-20 pointer-events-none" />
            <div className="absolute inset-0 bg-gradient-to-br from-primary-500/[0.06] via-transparent to-accent-500/[0.04] pointer-events-none" />

            <div className="absolute top-4 left-4 z-10 flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowControls((v) => !v)}
                className="w-10 h-10 rounded-2xl bg-white/5 border border-white/10 hover:bg-white/10 text-white/70 hover:text-white transition-colors flex items-center justify-center"
                title="Controls"
              >
                <Info size={16} />
              </button>
              {showControls && (
                <div className="px-3 py-2 rounded-2xl bg-dark-950/80 border border-white/10 text-[11px] text-white/70 backdrop-blur-xl">
                  Drag: rotate • Wheel: zoom • Right-drag: pan
                </div>
              )}
            </div>

            <Globe
              ref={globeRef}
              width={globeSize.w}
              height={globeSize.h}
              showNavInfo={false}
              globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
              bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
              backgroundColor="rgba(0,0,0,0)"
              pointsData={globePoints}
              pointLat="lat"
              pointLng="lng"
              pointAltitude="size"
              pointColor="color"
              pointLabel="label"
              ringsData={globeRingsData}
              ringLat="lat"
              ringLng="lng"
              ringColor={() => '#ef4444'}
              ringMaxRadius="maxR"
              ringPropagationSpeed="propagationSpeed"
              ringRepeatPeriod="repeatPeriod"
              onPointClick={(point) => {
                const country = MONITORED_COUNTRIES.find(
                  (item) => item.lat === point.lat && item.lng === point.lng
                );
                if (country) setSelectedCountry(country);
              }}
            />
          </div>

          <div className="mt-6 flex flex-wrap gap-2 max-h-48 overflow-y-auto">
            {MONITORED_COUNTRIES.map((country) => (
              <button
                key={country.code}
                onClick={() => setSelectedCountry(country)}
                className={`px-3 py-1.5 rounded-lg text-[11px] font-bold border transition-colors ${
                  selectedCountry.code === country.code
                    ? 'text-primary-500 border-primary-500/40 bg-primary-500/10'
                    : 'text-white/60 border-white/10 bg-white/5 hover:bg-white/10'
                }`}
              >
                {country.label} ({countryScores[country.code] ?? '—'})
              </button>
            ))}
          </div>
        </div>

        <aside className="space-y-4">
          <div className="p-5 rounded-2xl bg-dark-900/70 border border-white/10">
            <h3 className="text-sm font-black text-white uppercase tracking-wider mb-3">Country Profile</h3>
            {countryMeta ? (
              <div className="space-y-1.5 text-sm text-white/75">
                <div className="text-base font-black text-primary-500 flex items-center gap-2">
                  <span>{countryMeta.flag}</span>
                  <span>{countryMeta.name}</span>
                </div>
                <p><span className="text-white/40">Official:</span> {countryMeta.official}</p>
                <p><span className="text-white/40">Capital:</span> {countryMeta.capital}</p>
                <p><span className="text-white/40">Region:</span> {countryMeta.region} / {countryMeta.subregion}</p>
                <p><span className="text-white/40">Population:</span> {countryMeta.population}</p>
                <p><span className="text-white/40">Timezone:</span> {countryMeta.timezone}</p>
                <div className="mt-3 p-2 rounded-lg bg-white/5 border border-white/10">
                  <p className="text-[11px] font-black uppercase text-white/50 tracking-wider mb-1">Threat Level</p>
                  <div className="flex items-center justify-between">
                    <span className="text-primary-500 font-black uppercase">{riskLevel}</span>
                    <span className="text-white/60">{activityScore}/100</span>
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-white/40 text-sm">Unable to load country details.</p>
            )}
          </div>

          <div className="p-5 rounded-2xl bg-dark-900/70 border border-white/10">
            <h3 className="text-sm font-black text-white uppercase tracking-wider mb-3">Related CVEs</h3>
            {kevMatches.length > 0 ? (
              <div className="space-y-2">
                {kevMatches.map((item) => (
                  <div key={item.cve} className="px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-sm text-white/80">
                    <div className="flex items-center gap-2">
                      <ShieldAlert size={14} className="text-primary-500" />
                      <span className="font-black">{item.cve}</span>
                      <span className="text-[10px] text-white/40 ml-auto">{item.date_added || ''}</span>
                    </div>
                    {(item.vendor || item.product) && (
                      <div className="mt-1 text-[11px] text-white/60">
                        {item.vendor || 'Vendor'} {item.product ? `• ${item.product}` : ''}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : relatedCves.length > 0 ? (
              <div className="space-y-2">
                {relatedCves.map((cve) => (
                  <div key={cve} className="px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-sm text-white/80 flex items-center gap-2">
                    <ShieldAlert size={14} className="text-primary-500" />
                    {cve}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-white/40 text-sm">No CVE tokens found in current stream.</p>
            )}
          </div>

          <div className="p-5 rounded-2xl bg-dark-900/70 border border-white/10">
            <h3 className="text-sm font-black text-white uppercase tracking-wider mb-3">
              Latest Security Headlines ({selectedCountry.code})
            </h3>
            <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
              {intelItems.map((item, idx) => (
                <a
                  key={`${item.link}-${idx}`}
                  href={item.link}
                  target="_blank"
                  rel="noreferrer"
                  className="block p-3 rounded-xl bg-white/[0.03] border border-white/5 hover:border-primary-500/30 transition-colors"
                >
                  <p className="text-xs text-white/30 mb-1">{item.source || 'Feed'}</p>
                  <p className="text-sm text-white/80 line-clamp-2">{item.title}</p>
                  <span className="mt-2 inline-flex items-center gap-1 text-[11px] text-primary-500">
                    Open <ExternalLink size={12} />
                  </span>
                </a>
              ))}

              {!loading && intelItems.length === 0 && (
                <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300 text-sm flex items-center gap-2">
                  <AlertTriangle size={14} />
                  Intel feed unavailable right now.
                </div>
              )}
            </div>
          </div>
        </aside>
      </div>
    </section>
  );
};

export default GlobalThreatGlobe;
