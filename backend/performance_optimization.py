"""
PHASE 4 Step 8: Performance Optimization Engine
- Redis caching for leaderboards, user data, and frequently accessed data
- Database query optimization
- API response compression
- Pagination improvements
- Connection pooling
"""

import redis
import json
import gzip
import io
from functools import wraps
from typing import Optional, Dict, List, Any, Callable
from datetime import datetime, timedelta
from flask import request, jsonify
from sqlalchemy import text
import hashlib
import time


class RedisCache:
    """Redis cache manager for application-wide caching"""
    
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0, ttl: int = 3600):
        """Initialize Redis connection with connection pooling"""
        self.connection_pool = redis.ConnectionPool(
            host=host, 
            port=port, 
            db=db,
            max_connections=50,
            decode_responses=True
        )
        self.redis = redis.Redis(connection_pool=self.connection_pool)
        self.ttl = ttl
        self.stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0
        }
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            value = self.redis.get(key)
            if value:
                self.stats['hits'] += 1
                return json.loads(value) if isinstance(value, str) else value
            self.stats['misses'] += 1
            return None
        except Exception as e:
            print(f"Redis GET error: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        try:
            ttl = ttl or self.ttl
            self.redis.setex(key, ttl, json.dumps(value) if not isinstance(value, str) else value)
            self.stats['sets'] += 1
            return True
        except Exception as e:
            print(f"Redis SET error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            self.redis.delete(key)
            self.stats['deletes'] += 1
            return True
        except Exception as e:
            print(f"Redis DELETE error: {e}")
            return False
    
    def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        try:
            keys = self.redis.keys(pattern)
            if keys:
                self.redis.delete(*keys)
            return len(keys)
        except Exception as e:
            print(f"Redis DELETE PATTERN error: {e}")
            return 0
    
    def clear_all(self) -> bool:
        """Clear entire cache (use with caution)"""
        try:
            self.redis.flushdb()
            return True
        except Exception as e:
            print(f"Redis FLUSH error: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0
        return {
            'hits': self.stats['hits'],
            'misses': self.stats['misses'],
            'hit_rate': f"{hit_rate:.2f}%",
            'sets': self.stats['sets'],
            'deletes': self.stats['deletes'],
            'total_operations': total
        }
    
    def increment(self, key: str, amount: int = 1) -> int:
        """Increment counter"""
        return self.redis.incrby(key, amount)
    
    def add_to_set(self, key: str, *members) -> int:
        """Add members to a set"""
        return self.redis.sadd(key, *members)
    
    def get_set_members(self, key: str) -> set:
        """Get all members from a set"""
        return self.redis.smembers(key)
    
    def add_to_sorted_set(self, key: str, **kwargs) -> int:
        """Add members to sorted set with scores"""
        return self.redis.zadd(key, kwargs)
    
    def get_sorted_set_range(self, key: str, start: int = 0, end: int = -1, reverse: bool = True) -> List[tuple]:
        """Get range from sorted set with scores"""
        if reverse:
            return self.redis.zrevrange(key, start, end, withscores=True)
        return self.redis.zrange(key, start, end, withscores=True)


class CacheDecorator:
    """Decorator for caching function results"""
    
    def __init__(self, cache: RedisCache, ttl: Optional[int] = None, key_prefix: str = ""):
        self.cache = cache
        self.ttl = ttl
        self.key_prefix = key_prefix
    
    def __call__(self, func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            key_data = f"{self.key_prefix}:{func.__name__}:"
            key_data += ":".join(str(arg) for arg in args if not hasattr(arg, '__dict__'))
            key_data += ":".join(f"{k}={v}" for k, v in sorted(kwargs.items()))
            
            cache_key = hashlib.md5(key_data.encode()).hexdigest()
            
            # Try to get from cache
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            self.cache.set(cache_key, result, self.ttl)
            return result
        
        return wrapper


class LeaderboardCache:
    """Specialized caching for leaderboards with Redis sorted sets"""
    
    def __init__(self, cache: RedisCache):
        self.cache = cache
    
    def update_leaderboard(self, board_name: str, user_id: str, score: float):
        """Update user's score in leaderboard"""
        key = f"leaderboard:{board_name}"
        self.cache.add_to_sorted_set(key, **{user_id: score})
        self.cache.redis.expire(key, 86400)  # 24 hour TTL
    
    def get_leaderboard(self, board_name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get top users from leaderboard"""
        key = f"leaderboard:{board_name}"
        results = self.cache.get_sorted_set_range(key, 0, limit - 1, reverse=True)
        
        leaderboard = []
        for idx, (user_id, score) in enumerate(results, 1):
            leaderboard.append({
                'rank': idx,
                'user_id': user_id,
                'score': float(score)
            })
        return leaderboard
    
    def get_user_rank(self, board_name: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user's rank in leaderboard"""
        key = f"leaderboard:{board_name}"
        rank = self.cache.redis.zrevrank(key, user_id)
        score = self.cache.redis.zscore(key, user_id)
        
        if rank is not None and score is not None:
            return {
                'rank': rank + 1,
                'user_id': user_id,
                'score': float(score)
            }
        return None
    
    def clear_leaderboard(self, board_name: str):
        """Clear entire leaderboard"""
        key = f"leaderboard:{board_name}"
        self.cache.delete(key)


class QueryOptimizer:
    """Database query optimization utilities"""
    
    @staticmethod
    def add_indexes(db, models: List[Any]):
        """Create indexes for frequently queried columns"""
        index_queries = [
            # User indexes
            "CREATE INDEX IF NOT EXISTS idx_user_email ON user(email)",
            "CREATE INDEX IF NOT EXISTS idx_user_username ON user(username)",
            
            # Progress indexes
            "CREATE INDEX IF NOT EXISTS idx_progress_user_id ON progress(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_progress_course_id ON progress(course_id)",
            "CREATE INDEX IF NOT EXISTS idx_progress_user_course ON progress(user_id, course_id)",
            
            # Course indexes
            "CREATE INDEX IF NOT EXISTS idx_course_category ON course(category)",
            "CREATE INDEX IF NOT EXISTS idx_course_difficulty ON course(difficulty)",
            
            # Wiki article indexes
            "CREATE INDEX IF NOT EXISTS idx_wiki_author ON wiki_article(author_id)",
            "CREATE INDEX IF NOT EXISTS idx_wiki_category ON wiki_article(category)",
            "CREATE INDEX IF NOT EXISTS idx_wiki_created ON wiki_article(created_at)",
            
            # Game score indexes
            "CREATE INDEX IF NOT EXISTS idx_game_score_user ON game_score(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_game_score_game ON game_score(game_id)",
            "CREATE INDEX IF NOT EXISTS idx_game_score_date ON game_score(played_at)",
            
            # Mentor indexes
            "CREATE INDEX IF NOT EXISTS idx_mentor_user_id ON mentor(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_mentor_expertise ON mentor(expertise_areas)",
            
            # Bug bounty indexes
            "CREATE INDEX IF NOT EXISTS idx_bounty_user_id ON bug_bounty_submission(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_bounty_platform ON bug_bounty_submission(platform)",
            "CREATE INDEX IF NOT EXISTS idx_bounty_status ON bug_bounty_submission(status)",
        ]
        
        for query in index_queries:
            try:
                db.session.execute(text(query))
            except Exception as e:
                print(f"Index creation warning: {e}")
        
        db.session.commit()
    
    @staticmethod
    def optimize_queries(db):
        """Apply query optimization settings"""
        queries = [
            "PRAGMA cache_size = 10000",
            "PRAGMA synchronous = NORMAL",
            "PRAGMA temp_store = MEMORY",
            "PRAGMA query_only = FALSE",
            "PRAGMA foreign_keys = ON",
        ]
        
        for query in queries:
            try:
                db.session.execute(text(query))
            except Exception as e:
                print(f"PRAGMA warning: {e}")


class ResponseCompressor:
    """Compress API responses for bandwidth optimization"""
    
    @staticmethod
    def compress_response(data: str, min_size: int = 1000) -> tuple[bytes, bool]:
        """Compress response using gzip if beneficial"""
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        
        if len(data_bytes) < min_size:
            return data_bytes, False
        
        compressed = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed, mode='wb') as f:
            f.write(data_bytes)
        
        compressed_data = compressed.getvalue()
        
        if len(compressed_data) < len(data_bytes):
            return compressed_data, True
        return data_bytes, False
    
    @staticmethod
    def create_compression_middleware(app):
        """Create Flask middleware for automatic response compression"""
        @app.after_request
        def compress_response(response):
            if response.is_json and len(response.get_data()) > 1000:
                if 'gzip' in request.headers.get('Accept-Encoding', ''):
                    compressed_data, was_compressed = ResponseCompressor.compress_response(
                        response.get_data(as_text=True)
                    )
                    if was_compressed:
                        response.set_data(compressed_data)
                        response.headers['Content-Encoding'] = 'gzip'
                        response.headers['Content-Length'] = len(compressed_data)
            return response
        
        return app


class PaginationOptimizer:
    """Advanced pagination utilities"""
    
    @staticmethod
    def paginate_query(query, page: int = 1, per_page: int = 20, max_per_page: int = 100):
        """Optimize pagination with cursor-based approach"""
        per_page = min(per_page, max_per_page)
        
        total = query.count()
        total_pages = (total + per_page - 1) // per_page
        
        offset = (page - 1) * per_page
        items = query.offset(offset).limit(per_page).all()
        
        return {
            'items': items,
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        }
    
    @staticmethod
    def cursor_paginate(query, cursor: Optional[str] = None, limit: int = 20):
        """Cursor-based pagination (more efficient for large datasets)"""
        if cursor:
            items = query.filter(query.c[0] > cursor).limit(limit + 1).all()
        else:
            items = query.limit(limit + 1).all()
        
        has_more = len(items) > limit
        items = items[:limit]
        
        next_cursor = items[-1][0] if items and has_more else None
        
        return {
            'items': items,
            'next_cursor': str(next_cursor) if next_cursor else None,
            'has_more': has_more
        }


class ConnectionPool:
    """Database connection pooling optimization"""
    
    @staticmethod
    def configure_connection_pool(app, db):
        """Configure SQLAlchemy connection pool"""
        from sqlalchemy.pool import QueuePool
        
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'poolclass': QueuePool,
            'pool_size': 20,
            'max_overflow': 40,
            'pool_recycle': 3600,
            'pool_pre_ping': True,
            'echo': False,
            'connect_args': {
                'timeout': 30,
                'check_same_thread': False
            }
        }
        
        return app


class PerformanceMonitor:
    """Monitor API performance metrics"""
    
    def __init__(self):
        self.metrics = {
            'request_count': 0,
            'total_response_time': 0,
            'slowest_endpoints': [],
            'error_count': 0
        }
    
    def record_request(self, endpoint: str, duration: float, status_code: int):
        """Record request metrics"""
        self.metrics['request_count'] += 1
        self.metrics['total_response_time'] += duration
        
        if status_code >= 400:
            self.metrics['error_count'] += 1
        
        # Track slowest endpoints
        self.metrics['slowest_endpoints'].append({
            'endpoint': endpoint,
            'duration': duration,
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only last 100 slow requests
        if len(self.metrics['slowest_endpoints']) > 100:
            self.metrics['slowest_endpoints'] = self.metrics['slowest_endpoints'][-100:]
    
    def get_average_response_time(self) -> float:
        """Get average response time"""
        if self.metrics['request_count'] == 0:
            return 0
        return self.metrics['total_response_time'] / self.metrics['request_count']
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all performance metrics"""
        return {
            'total_requests': self.metrics['request_count'],
            'average_response_time_ms': round(self.get_average_response_time() * 1000, 2),
            'total_errors': self.metrics['error_count'],
            'error_rate': f"{(self.metrics['error_count'] / self.metrics['request_count'] * 100) if self.metrics['request_count'] > 0 else 0:.2f}%",
            'slowest_endpoints': sorted(
                self.metrics['slowest_endpoints'],
                key=lambda x: x['duration'],
                reverse=True
            )[:10]
        }


# Global instances
cache = None
leaderboard_cache = None
performance_monitor = PerformanceMonitor()


def init_performance(app, db):
    """Initialize performance optimization"""
    global cache, leaderboard_cache
    
    try:
        cache = RedisCache()
        leaderboard_cache = LeaderboardCache(cache)
        
        # Test Redis connection
        cache.redis.ping()
        print("✓ Redis cache initialized successfully")
    except Exception as e:
        print(f"⚠ Redis not available: {e}")
        cache = None
        leaderboard_cache = None
    
    # Configure connection pooling
    ConnectionPool.configure_connection_pool(app, db)
    
    # Optimize database queries
    QueryOptimizer.optimize_queries(db)
    
    # Add indexes
    QueryOptimizer.add_indexes(db, [])
    
    # Create compression middleware
    ResponseCompressor.create_compression_middleware(app)
    
    # Add performance monitoring middleware
    @app.before_request
    def before_request():
        request.start_time = time.time()
    
    @app.after_request
    def after_request(response):
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time
            performance_monitor.record_request(
                request.endpoint or 'unknown',
                duration,
                response.status_code
            )
        return response


__all__ = [
    'RedisCache',
    'CacheDecorator',
    'LeaderboardCache',
    'QueryOptimizer',
    'ResponseCompressor',
    'PaginationOptimizer',
    'ConnectionPool',
    'PerformanceMonitor',
    'cache',
    'leaderboard_cache',
    'performance_monitor',
    'init_performance'
]
