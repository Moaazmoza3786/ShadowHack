"""
Intel Manager - Cybersecurity Intelligence Engine 🛰️
Fetches, parses, and summarizes security news, vulnerabilities, and writeups
from professional sources (RSS, APIs, etc.)
"""

import feedparser
import logging
from datetime import datetime
import threading
import time
from typing import List, Dict, Any, Optional
import re
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('IntelManager')

class IntelManager:
    COUNTRY_KEYWORDS = {
        'US': ['united states', 'usa', 'u.s.', 'america', 'cisa', 'fbi'],
        'GB': ['united kingdom', 'uk', 'britain', 'england', 'nca'],
        'DE': ['germany', 'german', 'bsi'],
        'AE': ['uae', 'united arab emirates', 'dubai', 'abu dhabi'],
        'IN': ['india', 'indian', 'cert-in'],
        'SG': ['singapore', 'singaporean', 'csa singapore'],
        'JP': ['japan', 'japanese', 'jpcert'],
        'AU': ['australia', 'australian', 'acsc'],
        'EU': ['europe', 'eu', 'european union', 'enisa'],
        'MENA': ['mena', 'middle east', 'north africa'],
        'LATAM': ['latam', 'latin america', 'south america'],
        'AFRICA': ['africa', 'african'],
    }

    """
    Manages live intelligence feeds for the platform.
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    DEFAULT_FEEDS = {
        'news': [
            # Official/primary sources first
            {'name': 'CISA Current Activity', 'url': 'https://www.cisa.gov/uscert/ncas/current-activity.xml', 'category': 'Advisory'},
            {'name': 'CISA Alerts', 'url': 'https://www.cisa.gov/uscert/ncas/alerts.xml', 'category': 'Alert'},
            # High-quality industry reporting
            {'name': 'BleepingComputer', 'url': 'https://www.bleepingcomputer.com/feed/', 'category': 'News'},
            {'name': 'Krebs on Security', 'url': 'https://krebsonsecurity.com/feed/', 'category': 'News'},
            {'name': 'The Hacker News', 'url': 'https://feeds.feedburner.com/TheHackersNews', 'category': 'News'},
        ],
        'vulnerabilities': [
            {'name': 'ZDI Blog', 'url': 'https://www.zerodayinitiative.com/blog?format=rss', 'category': 'Research'},
            # Note: KEV CVEs are provided via /api/intel/kev (CISA JSON), not RSS.
        ],
        'writeups': [
            {'name': 'Hack The Box Blog', 'url': 'https://www.hackthebox.com/blog/rss', 'category': 'Writeup'},
            {'name': 'TryHackMe Blog', 'url': 'https://blog.tryhackme.com/rss/', 'category': 'Writeup'}
        ]
    }

    def __init__(self):
        self.cache = {
            'news': [],
            'vulnerabilities': [],
            'writeups': [],
            'last_updated': None
        }
        self.kev_cache = {
            'items': [],
            'last_updated': None,
            'source_updated': None,
            'fetched_at': 0.0,
        }
        self.lock = threading.Lock()
        self._start_auto_refresh()

    def _start_auto_refresh(self, interval_seconds: int = 600):
        """Start background thread to refresh feeds periodically."""
        def refresh_loop():
            while True:
                try:
                    self.refresh_all_feeds()
                except Exception as e:
                    logger.error(f"Error refreshing feeds: {e}")
                time.sleep(interval_seconds)

        thread = threading.Thread(target=refresh_loop, daemon=True)
        thread.start()
        logger.info("📡 Intel auto-refresh background task started")

    def refresh_all_feeds(self):
        """Fetch and parse all configured feeds"""
        logger.info("🔄 Refreshing all intelligence feeds...")
        new_cache = {
            'news': [],
            'vulnerabilities': [],
            'writeups': [],
            'last_updated': datetime.now().isoformat()
        }

        for feed_type, feeds in self.DEFAULT_FEEDS.items():
            for feed_config in feeds:
                try:
                    entries = self._fetch_feed(feed_config)
                    new_cache[feed_type].extend(entries)
                except Exception as e:
                    logger.warning(f"Failed to fetch {feed_config['name']}: {e}")

        # Refresh KEV periodically (separate from RSS)
        self._maybe_refresh_kev()

        # Sort all lists by date (newest first)
        for feed_type in ['news', 'vulnerabilities', 'writeups']:
            new_cache[feed_type].sort(key=lambda x: x.get('published_parsed', ''), reverse=True)
            # Cap at 50 entries per type
            new_cache[feed_type] = new_cache[feed_type][:50]

        with self.lock:
            self.cache = new_cache
        
        logger.info(f"✅ Feeds refreshed. News: {len(self.cache['news'])}, Vulns: {len(self.cache['vulnerabilities'])}, Writeups: {len(self.cache['writeups'])}")

    def _maybe_refresh_kev(self, ttl_seconds: int = 6 * 3600):
        """Refresh CISA KEV cache if stale."""
        now = time.time()
        with self.lock:
            fetched_at = float(self.kev_cache.get('fetched_at') or 0.0)
        if now - fetched_at < ttl_seconds and fetched_at > 0:
            return
        try:
            self.refresh_kev()
        except Exception as e:
            logger.warning(f"Failed to refresh CISA KEV: {e}")

    def refresh_kev(self):
        """Fetch CISA Known Exploited Vulnerabilities (KEV) catalog (JSON)."""
        r = requests.get(
            self.KEV_URL,
            timeout=8,
            headers={'User-Agent': 'ShadowHackIntel/1.0'},
        )
        r.raise_for_status()
        data = r.json() if r.content else {}
        raw_items = data.get('vulnerabilities', []) if isinstance(data, dict) else []

        items = []
        for v in raw_items:
            if not isinstance(v, dict):
                continue
            cve = (v.get('cveID') or v.get('cve') or '').strip().upper()
            if not cve:
                continue
            items.append({
                'cve': cve,
                'vendor': v.get('vendorProject'),
                'product': v.get('product'),
                'name': v.get('vulnerabilityName') or v.get('vulnerability') or v.get('vulnerabilityName'),
                'date_added': v.get('dateAdded'),
                'due_date': v.get('dueDate'),
                'short_description': v.get('shortDescription'),
                'required_action': v.get('requiredAction'),
                'notes': v.get('notes'),
                'known_ransomware_campaign_use': v.get('knownRansomwareCampaignUse'),
            })

        items.sort(key=lambda x: x.get('date_added') or '', reverse=True)

        with self.lock:
            self.kev_cache = {
                'items': items[:2000],
                'last_updated': datetime.now().isoformat(),
                'source_updated': (data.get('dateReleased') or data.get('catalogVersion') or data.get('dateCreated')) if isinstance(data, dict) else None,
                'fetched_at': time.time(),
            }

    def get_kev(self, cves: Optional[List[str]] = None, limit: int = 10) -> Dict[str, Any]:
        """Get KEV entries (optionally filtered by CVE list)."""
        self._maybe_refresh_kev()
        with self.lock:
            items = list(self.kev_cache.get('items') or [])
            last_updated = self.kev_cache.get('last_updated')
            source_updated = self.kev_cache.get('source_updated')

        if cves:
            wanted = {c.strip().upper() for c in cves if c and c.strip()}
            items = [i for i in items if i.get('cve') in wanted]

        return {
            'success': True,
            'count': len(items),
            'last_updated': last_updated,
            'source_updated': source_updated,
            'items': items[: max(1, int(limit or 10))],
        }

    def _fetch_feed(self, feed_config: Dict[str, str]) -> List[Dict[str, Any]]:
        """Parse an RSS feed into a standard format"""
        feed = feedparser.parse(feed_config['url'])
        entries = []
        
        for entry in feed.entries:
            # Standardize entry format
            standard_entry = {
                'id': entry.get('id', entry.get('link')),
                'title': entry.get('title'),
                'link': entry.get('link'),
                'summary': entry.get('summary', entry.get('description', ''))[:500], # Trucate long summaries
                'published': entry.get('published', ''),
                'published_parsed': entry.get('published_parsed', None),
                'source': feed_config['name'],
                'category': feed_config['category'],
                'author': entry.get('author', 'Anonymous')
            }
            # Remove HTML tags from summary if needed, but keeping for now as frontend can handle
            entries.append(standard_entry)
            
        return entries

    def _filter_by_country(self, items: List[Dict[str, Any]], country: str) -> List[Dict[str, Any]]:
        """Filter intel items by country/region keyword match."""
        country_norm = (country or '').strip().upper()
        if not country_norm:
            return items

        keywords = self.COUNTRY_KEYWORDS.get(country_norm, [country.lower()])
        filtered = []

        for item in items:
            haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
            if any(keyword in haystack for keyword in keywords):
                filtered.append(item)

        return filtered

    def _extract_cves(self, items: List[Dict[str, Any]]) -> List[str]:
        """Extract unique CVE IDs from feed items."""
        cve_regex = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
        found = []
        seen = set()
        for item in items:
            haystack = f"{item.get('title', '')} {item.get('summary', '')}"
            matches = cve_regex.findall(haystack)
            for m in matches:
                cve = m.upper()
                if cve not in seen:
                    seen.add(cve)
                    found.append(cve)
        return found

    def get_intel(self, feed_type: str = 'news', category: Optional[str] = None, country: Optional[str] = None) -> Dict[str, Any]:
        """Get cached intel items"""
        with self.lock:
            items = self.cache.get(feed_type, [])
            if category:
                items = [i for i in items if i['category'] == category]
            if country:
                items = self._filter_by_country(items, country)
            
            return {
                'success': True,
                'type': feed_type,
                'count': len(items),
                'country': country,
                'cves': self._extract_cves(items[:30]),
                'last_updated': self.cache['last_updated'],
                'items': items
            }

# Global instance
intel_manager = IntelManager()

def register_intel_routes(app):
    """Register intel API routes with Flask app"""
    from flask import jsonify, request

    @app.route('/api/intel/news', methods=['GET'])
    def get_news():
        category = request.args.get('category')
        country = request.args.get('country')
        return jsonify(intel_manager.get_intel('news', category, country))

    @app.route('/api/intel/vulnerabilities', methods=['GET'])
    def get_vulnerabilities():
        return jsonify(intel_manager.get_intel('vulnerabilities'))

    @app.route('/api/intel/writeups', methods=['GET'])
    def get_writeups():
        return jsonify(intel_manager.get_intel('writeups'))

    @app.route('/api/intel/refresh', methods=['POST'])
    def manual_refresh():
        # Optional: Add simple auth check here
        intel_manager.refresh_all_feeds()
        return jsonify({'success': True, 'message': 'Refresh initiated'})

    @app.route('/api/intel/kev', methods=['GET'])
    def get_kev():
        cves_param = (request.args.get('cves') or '').strip()
        cves = [c.strip() for c in cves_param.split(',') if c.strip()] if cves_param else None
        try:
            limit = int(request.args.get('limit') or 10)
        except Exception:
            limit = 10
        return jsonify(intel_manager.get_kev(cves=cves, limit=limit))
