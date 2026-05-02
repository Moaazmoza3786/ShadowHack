import React, { useRef, useEffect, useState } from 'react';

const AnimatedCounter = ({ value, duration = 1500, prefix = '', suffix = '', decimals = 0 }) => {
  const ref = useRef(null);
  const [displayValue, setDisplayValue] = useState(0);
  const [hasInView, setHasInView] = useState(false);

  useEffect(() => {
    if (hasInView) {
      let startTime = null;
      const startValue = 0;
      const endValue = value;

      const animate = (currentTime) => {
        if (!startTime) startTime = currentTime;
        const progress = Math.min((currentTime - startTime) / duration, 1);
        const easeOutExpo = (t) => t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
        const currentValue = startValue + (endValue - startValue) * easeOutExpo(progress);

        setDisplayValue(currentValue);

        if (progress < 1) {
          requestAnimationFrame(animate);
        } else {
          setDisplayValue(endValue);
        }
      };

      requestAnimationFrame(animate);
    }
  }, [hasInView, value, duration]);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          setHasInView(true);
          observer.disconnect();
          break;
        }
      }
    }, { root: null, threshold: 0.1 });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const formatNumber = (num) => {
    if (decimals > 0) {
      return num.toFixed(decimals);
    }
    return Math.round(num).toLocaleString();
  };

  return <span ref={ref}>{prefix}{formatNumber(displayValue)}{suffix}</span>;
};

export default AnimatedCounter;
