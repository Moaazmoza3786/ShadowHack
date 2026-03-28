"""
Wiki and Knowledge Base API Routes
Handles article CRUD, voting, comments, and full-text search
"""

from flask import Blueprint, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps
from sqlalchemy import or_, and_, func
import re

wiki_bp = Blueprint('wiki', __name__, url_prefix='/api/wiki')

# Import models from main app
from models import db, User, WikiArticle, WikiComment, WikiVote

# Auth decorator
def token_required(f):
    """Verify JWT token from header"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Missing authentication token'}), 401
        
        # In production, verify JWT token here
        # For now, we'll accept any non-empty token
        try:
            # This would normally decode JWT
            user_id = request.headers.get('X-User-ID')
            if not user_id:
                return jsonify({'error': 'Invalid token'}), 401
            kwargs['user_id'] = int(user_id)
            return f(*args, **kwargs)
        except:
            return jsonify({'error': 'Invalid token'}), 401
    
    return decorated


# ==================== ARTICLE ENDPOINTS ====================

@wiki_bp.route('/articles', methods=['GET'])
def get_articles():
    """
    Get all published articles with optional filtering
    Query params: 
    - category: Filter by category
    - difficulty: Filter by difficulty level
    - tags: Comma-separated tags
    - search: Full-text search
    - featured: Only featured articles (true/false)
    - page: Page number (default 1)
    - per_page: Items per page (default 10)
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        category = request.args.get('category')
        difficulty = request.args.get('difficulty')
        tags = request.args.get('tags')
        search = request.args.get('search')
        featured = request.args.get('featured', type=lambda x: x.lower() == 'true')
        
        # Base query
        query = WikiArticle.query.filter(
            WikiArticle.is_published == True,
            WikiArticle.is_archived == False
        )
        
        # Apply filters
        if category:
            query = query.filter(WikiArticle.category.ilike(f'%{category}%'))
        
        if difficulty:
            query = query.filter(WikiArticle.difficulty == difficulty)
        
        if featured:
            query = query.filter(WikiArticle.is_featured == True)
        
        if tags:
            tag_list = [t.strip().lower() for t in tags.split(',')]
            # Filter by any matching tag
            for tag in tag_list:
                query = query.filter(
                    func.json_contains(WikiArticle.tags, f'"{tag}"')
                )
        
        if search:
            # Full-text search on title, summary, and tags
            search_term = f'%{search}%'
            query = query.filter(
                or_(
                    WikiArticle.title.ilike(search_term),
                    WikiArticle.summary.ilike(search_term),
                    WikiArticle.content.ilike(search_term),
                    WikiArticle.tags.astext.ilike(search_term)
                )
            )
        
        # Sort by newest first
        query = query.order_by(WikiArticle.created_at.desc())
        
        # Paginate
        paginated = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'articles': [article.to_dict() for article in paginated.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated.total,
                'pages': paginated.pages
            }
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/articles/<int:article_id>', methods=['GET'])
def get_article(article_id):
    """
    Get a single article by ID
    Increments view count
    """
    try:
        article = WikiArticle.query.get(article_id)
        
        if not article or article.is_archived:
            return jsonify({'error': 'Article not found'}), 404
        
        # Increment view count
        article.views_count += 1
        db.session.commit()
        
        # Get comments
        comments = WikiComment.query.filter(
            WikiComment.article_id == article_id,
            WikiComment.is_deleted == False,
            WikiComment.is_approved == True
        ).order_by(WikiComment.created_at.desc()).all()
        
        # Get user's vote status
        user_vote = None
        user_id = request.headers.get('X-User-ID')
        if user_id:
            vote = WikiVote.query.filter_by(
                article_id=article_id,
                user_id=int(user_id)
            ).first()
            user_vote = vote.value if vote else None
        
        article_data = article.to_dict(include_content=True)
        article_data['comments'] = [comment.to_dict() for comment in comments]
        article_data['user_vote'] = user_vote
        
        return jsonify({
            'success': True,
            'article': article_data
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/articles', methods=['POST'])
@token_required
def create_article(user_id):
    """
    Create a new wiki article
    Requires authentication
    """
    try:
        data = request.json
        
        # Validate required fields
        required = ['title', 'content', 'category', 'difficulty']
        if not all(field in data for field in required):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Generate slug from title
        slug = re.sub(r'[^a-z0-9]+', '-', data['title'].lower()).strip('-')
        
        # Check slug uniqueness
        if WikiArticle.query.filter_by(slug=slug).first():
            slug = f"{slug}-{int(datetime.utcnow().timestamp())}"
        
        article = WikiArticle(
            author_id=user_id,
            title=data['title'],
            slug=slug,
            content=data['content'],
            summary=data.get('summary', ''),
            category=data['category'],
            difficulty=data['difficulty'],
            tags=data.get('tags', []),
            is_published=data.get('is_published', True)
        )
        
        db.session.add(article)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'article': article.to_dict(),
            'message': 'Article created successfully'
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/articles/<int:article_id>', methods=['PUT'])
@token_required
def update_article(user_id, article_id):
    """
    Update a wiki article
    Only author or admin can update
    """
    try:
        article = WikiArticle.query.get(article_id)
        
        if not article:
            return jsonify({'error': 'Article not found'}), 404
        
        # Check authorization
        user = User.query.get(user_id)
        if article.author_id != user_id and user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.json
        
        # Update fields
        if 'title' in data:
            article.title = data['title']
        
        if 'content' in data:
            article.content = data['content']
            article.last_edited_by = user_id
        
        if 'summary' in data:
            article.summary = data['summary']
        
        if 'category' in data:
            article.category = data['category']
        
        if 'difficulty' in data:
            article.difficulty = data['difficulty']
        
        if 'tags' in data:
            article.tags = data['tags']
        
        if 'is_published' in data:
            article.is_published = data['is_published']
        
        article.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'article': article.to_dict(),
            'message': 'Article updated successfully'
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/articles/<int:article_id>', methods=['DELETE'])
@token_required
def delete_article(user_id, article_id):
    """
    Archive (soft delete) a wiki article
    Only author or admin can delete
    """
    try:
        article = WikiArticle.query.get(article_id)
        
        if not article:
            return jsonify({'error': 'Article not found'}), 404
        
        # Check authorization
        user = User.query.get(user_id)
        if article.author_id != user_id and user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        article.is_archived = True
        article.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Article archived successfully'
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== VOTING ENDPOINTS ====================

@wiki_bp.route('/articles/<int:article_id>/vote', methods=['POST'])
@token_required
def vote_article(user_id, article_id):
    """
    Vote on an article (upvote or downvote)
    """
    try:
        article = WikiArticle.query.get(article_id)
        
        if not article:
            return jsonify({'error': 'Article not found'}), 404
        
        data = request.json
        vote_value = data.get('value', 1)  # 1 for upvote, -1 for downvote
        
        if vote_value not in [1, -1]:
            return jsonify({'error': 'Invalid vote value'}), 400
        
        # Check if user already voted
        existing_vote = WikiVote.query.filter_by(
            article_id=article_id,
            user_id=user_id
        ).first()
        
        if existing_vote:
            # Update existing vote
            old_value = existing_vote.value
            existing_vote.value = vote_value
            
            # Update article counts
            if old_value == 1:
                article.upvotes_count -= 1
            else:
                article.downvotes_count -= 1
            
            if vote_value == 1:
                article.upvotes_count += 1
            else:
                article.downvotes_count += 1
        else:
            # Create new vote
            vote = WikiVote(
                article_id=article_id,
                user_id=user_id,
                value=vote_value
            )
            db.session.add(vote)
            
            # Update article counts
            if vote_value == 1:
                article.upvotes_count += 1
            else:
                article.downvotes_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'upvotes': article.upvotes_count,
            'downvotes': article.downvotes_count,
            'user_vote': vote_value
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/articles/<int:article_id>/unvote', methods=['POST'])
@token_required
def unvote_article(user_id, article_id):
    """
    Remove vote from an article
    """
    try:
        article = WikiArticle.query.get(article_id)
        
        if not article:
            return jsonify({'error': 'Article not found'}), 404
        
        vote = WikiVote.query.filter_by(
            article_id=article_id,
            user_id=user_id
        ).first()
        
        if vote:
            # Update article counts
            if vote.value == 1:
                article.upvotes_count -= 1
            else:
                article.downvotes_count -= 1
            
            db.session.delete(vote)
            db.session.commit()
        
        return jsonify({
            'success': True,
            'upvotes': article.upvotes_count,
            'downvotes': article.downvotes_count,
            'user_vote': None
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== COMMENT ENDPOINTS ====================

@wiki_bp.route('/articles/<int:article_id>/comments', methods=['GET'])
def get_comments(article_id):
    """
    Get all comments on an article
    """
    try:
        article = WikiArticle.query.get(article_id)
        
        if not article:
            return jsonify({'error': 'Article not found'}), 404
        
        comments = WikiComment.query.filter(
            WikiComment.article_id == article_id,
            WikiComment.is_deleted == False,
            WikiComment.is_approved == True
        ).order_by(WikiComment.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'comments': [comment.to_dict() for comment in comments],
            'total': len(comments)
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/articles/<int:article_id>/comments', methods=['POST'])
@token_required
def create_comment(user_id, article_id):
    """
    Create a comment on an article
    """
    try:
        article = WikiArticle.query.get(article_id)
        
        if not article:
            return jsonify({'error': 'Article not found'}), 404
        
        data = request.json
        
        if 'content' not in data or not data['content'].strip():
            return jsonify({'error': 'Comment content is required'}), 400
        
        comment = WikiComment(
            article_id=article_id,
            author_id=user_id,
            content=data['content']
        )
        
        db.session.add(comment)
        article.comments_count += 1
        db.session.commit()
        
        return jsonify({
            'success': True,
            'comment': comment.to_dict(),
            'message': 'Comment created successfully'
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/comments/<int:comment_id>', methods=['DELETE'])
@token_required
def delete_comment(user_id, comment_id):
    """
    Delete a comment
    Only author or admin can delete
    """
    try:
        comment = WikiComment.query.get(comment_id)
        
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404
        
        # Check authorization
        user = User.query.get(user_id)
        if comment.author_id != user_id and user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        comment.is_deleted = True
        comment.article.comments_count -= 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Comment deleted successfully'
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==================== SEARCH & DISCOVERY ====================

@wiki_bp.route('/search', methods=['GET'])
def search_articles():
    """
    Full-text search across all articles
    """
    try:
        query = request.args.get('q', '')
        category = request.args.get('category')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        if not query:
            return jsonify({'error': 'Search query is required'}), 400
        
        # Search query
        search_term = f'%{query}%'
        articles_query = WikiArticle.query.filter(
            WikiArticle.is_published == True,
            WikiArticle.is_archived == False,
            or_(
                WikiArticle.title.ilike(search_term),
                WikiArticle.summary.ilike(search_term),
                WikiArticle.content.ilike(search_term)
            )
        )
        
        if category:
            articles_query = articles_query.filter(WikiArticle.category == category)
        
        # Order by relevance (title match first, then updated_at)
        articles_query = articles_query.order_by(
            func.length(WikiArticle.title),
            WikiArticle.updated_at.desc()
        )
        
        paginated = articles_query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'articles': [article.to_dict() for article in paginated.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated.total,
                'pages': paginated.pages
            }
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/categories', methods=['GET'])
def get_categories():
    """
    Get all available categories
    """
    try:
        categories = db.session.query(WikiArticle.category).filter(
            WikiArticle.is_published == True,
            WikiArticle.is_archived == False
        ).distinct().all()
        
        return jsonify({
            'success': True,
            'categories': [cat[0] for cat in categories]
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/trending', methods=['GET'])
def get_trending():
    """
    Get trending articles (by views)
    """
    try:
        days = request.args.get('days', 30, type=int)
        limit = request.args.get('limit', 10, type=int)
        
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        articles = WikiArticle.query.filter(
            WikiArticle.is_published == True,
            WikiArticle.is_archived == False,
            WikiArticle.created_at >= cutoff
        ).order_by(WikiArticle.views_count.desc()).limit(limit).all()
        
        return jsonify({
            'success': True,
            'articles': [article.to_dict() for article in articles]
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/stats', methods=['GET'])
def get_wiki_stats():
    """
    Get wiki platform statistics
    """
    try:
        total_articles = WikiArticle.query.filter(
            WikiArticle.is_published == True,
            WikiArticle.is_archived == False
        ).count()
        
        total_comments = WikiComment.query.filter(
            WikiComment.is_deleted == False
        ).count()
        
        total_views = db.session.query(func.sum(WikiArticle.views_count)).scalar() or 0
        
        active_contributors = db.session.query(
            func.count(func.distinct(WikiArticle.author_id))
        ).filter(WikiArticle.is_published == True).scalar() or 0
        
        # Top contributors
        top_contributors = db.session.query(
            User.id,
            User.username,
            User.avatar_url,
            func.count(WikiArticle.id).label('article_count')
        ).join(WikiArticle).filter(
            WikiArticle.is_published == True
        ).group_by(User.id).order_by(
            func.count(WikiArticle.id).desc()
        ).limit(5).all()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_articles': total_articles,
                'total_comments': total_comments,
                'total_views': int(total_views),
                'active_contributors': active_contributors,
                'top_contributors': [
                    {
                        'username': tc[1],
                        'avatar_url': tc[2],
                        'article_count': tc[3]
                    } for tc in top_contributors
                ]
            }
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== USER ARTICLE MANAGEMENT ====================

@wiki_bp.route('/my-articles', methods=['GET'])
@token_required
def get_my_articles(user_id):
    """
    Get articles written by authenticated user
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        query = WikiArticle.query.filter_by(author_id=user_id)
        paginated = query.order_by(WikiArticle.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'articles': [article.to_dict() for article in paginated.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated.total,
                'pages': paginated.pages
            }
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@wiki_bp.route('/featured', methods=['GET'])
def get_featured_articles():
    """
    Get featured articles
    """
    try:
        articles = WikiArticle.query.filter(
            WikiArticle.is_featured == True,
            WikiArticle.is_published == True,
            WikiArticle.is_archived == False
        ).order_by(WikiArticle.views_count.desc()).limit(6).all()
        
        return jsonify({
            'success': True,
            'articles': [article.to_dict() for article in articles]
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
