"""
Certification Marketplace API Routes
Handles buying, selling, verifying, and analytics for digital credentials
"""

from flask import Blueprint, jsonify, request
from functools import wraps
import jwt
import os
from datetime import datetime, timedelta

from models import (
    db, User, CertificationTemplate, UserCertification, 
    CertMarketplaceTrade, EmployerVerification
)

marketplace_bp = Blueprint('marketplace', __name__, url_prefix='/api/marketplace')


def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            secret_key = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
            data = jwt.decode(token, secret_key, algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated


# ==================== MARKETPLACE ENDPOINTS ====================

@marketplace_bp.route('/certificates', methods=['GET'])
def get_all_certificates():
    """Get all available certifications in marketplace"""
    limit = request.args.get('limit', 50, type=int)
    search = request.args.get('search', '')
    
    query = CertificationTemplate.query
    if search:
        query = query.filter(
            (CertificationTemplate.name.ilike(f'%{search}%')) |
            (CertificationTemplate.issuer.ilike(f'%{search}%'))
        )
    
    templates = query.order_by(CertificationTemplate.trend_24h.desc()).limit(limit).all()
    
    return jsonify({
        'success': True,
        'certificates': [cert.to_dict() for cert in templates],
        'total': CertificationTemplate.query.count()
    })


@marketplace_bp.route('/certificates/<int:cert_id>', methods=['GET'])
def get_certificate_detail(cert_id):
    """Get detailed information about a specific certificate"""
    cert = CertificationTemplate.query.get(cert_id)
    if not cert:
        return jsonify({'error': 'Certificate not found'}), 404
    
    # Get market stats
    active_trades = CertMarketplaceTrade.query.filter_by(
        cert_id=cert_id,
        status='completed'
    ).all()
    
    recent_price = None
    if active_trades:
        recent = active_trades[-1]
        recent_price = recent.trade_price
    
    return jsonify({
        'success': True,
        'certificate': cert.to_dict(),
        'recent_price': recent_price,
        'active_listings': cert.active_listings,
        'verified_count': cert.verified_count
    })


@marketplace_bp.route('/my-certificates', methods=['GET'])
@token_required
def get_user_certificates(current_user):
    """Get all certificates owned by current user"""
    user_certs = UserCertification.query.filter_by(user_id=current_user.id).all()
    
    certs = []
    for cert in user_certs:
        cert_dict = cert.to_dict()
        cert_dict['suggested_price'] = cert.template.base_price
        cert_dict['listed'] = cert.for_sale
        certs.append(cert_dict)
    
    return jsonify({
        'success': True,
        'certificates': certs,
        'total': len(certs)
    })


@marketplace_bp.route('/buy/<int:cert_template_id>', methods=['POST'])
@token_required
def buy_certificate(current_user, cert_template_id):
    """Buy a certification from marketplace"""
    data = request.get_json()
    price = data.get('price', 0)
    
    if price <= 0:
        return jsonify({'error': 'Invalid price'}), 400
    
    # Check if user already owns this cert
    existing = UserCertification.query.filter_by(
        user_id=current_user.id,
        template_id=cert_template_id
    ).first()
    
    if existing:
        return jsonify({'error': 'You already own this certification'}), 400
    
    # Verify template exists
    template = CertificationTemplate.query.get(cert_template_id)
    if not template:
        return jsonify({'error': 'Certificate template not found'}), 404
    
    # Create new user certification
    new_cert = UserCertification(
        user_id=current_user.id,
        template_id=cert_template_id,
        earned_at=datetime.utcnow(),
        is_verified=True
    )
    
    db.session.add(new_cert)
    
    # Update user XP (reward for obtaining cert)
    current_user.xp_points += 100
    
    # Update marketplace stats
    template.active_listings -= 1
    template.verified_count += 1
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'Successfully purchased {template.name}!',
        'certificate': new_cert.to_dict(),
        'xp_earned': 100
    })


@marketplace_bp.route('/list/<int:cert_id>', methods=['POST'])
@token_required
def list_certificate_for_sale(current_user, cert_id):
    """List a user's certificate for sale on marketplace"""
    data = request.get_json()
    listing_price = data.get('listing_price', 0)
    
    if listing_price <= 0:
        return jsonify({'error': 'Invalid listing price'}), 400
    
    cert = UserCertification.query.get(cert_id)
    if not cert:
        return jsonify({'error': 'Certificate not found'}), 404
    
    if cert.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if cert.for_sale:
        return jsonify({'error': 'Certificate is already listed'}), 400
    
    # List the certificate
    cert.for_sale = True
    cert.listing_price = listing_price
    
    # Update template stats
    cert.template.active_listings += 1
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Certificate listed for sale!',
        'listing_price': listing_price
    })


@marketplace_bp.route('/unlist/<int:cert_id>', methods=['POST'])
@token_required
def unlist_certificate(current_user, cert_id):
    """Remove a certificate from marketplace"""
    cert = UserCertification.query.get(cert_id)
    if not cert:
        return jsonify({'error': 'Certificate not found'}), 404
    
    if cert.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if not cert.for_sale:
        return jsonify({'error': 'Certificate is not listed'}), 400
    
    cert.for_sale = False
    cert.listing_price = None
    cert.template.active_listings -= 1
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Listing removed'})


@marketplace_bp.route('/listings', methods=['GET'])
def get_active_listings():
    """Get all active certificate listings"""
    limit = request.args.get('limit', 100, type=int)
    template_id = request.args.get('template_id', type=int)
    
    query = UserCertification.query.filter_by(for_sale=True)
    if template_id:
        query = query.filter_by(template_id=template_id)
    
    listings = query.limit(limit).all()
    
    result = []
    for listing in listings:
        user = User.query.get(listing.user_id)
        result.append({
            'id': listing.id,
            'certificate': listing.template.to_dict(),
            'seller': {
                'id': user.id,
                'username': user.username,
                'avatar_url': user.avatar_url
            },
            'listing_price': listing.listing_price,
            'listed_at': listing.updated_at.isoformat()
        })
    
    return jsonify({
        'success': True,
        'listings': result,
        'total': len(result)
    })


# ==================== TRADING ====================

@marketplace_bp.route('/trade/<int:listing_id>', methods=['POST'])
@token_required
def purchase_from_listing(current_user, listing_id):
    """Purchase a certificate from another user's listing"""
    cert = UserCertification.query.get(listing_id)
    if not cert:
        return jsonify({'error': 'Listing not found'}), 404
    
    if not cert.for_sale:
        return jsonify({'error': 'Certificate is not for sale'}), 400
    
    if cert.user_id == current_user.id:
        return jsonify({'error': 'Cannot buy your own certificate'}), 400
    
    seller = User.query.get(cert.user_id)
    price = cert.listing_price
    
    # Create trade record
    platform_fee = price * 0.1  # 10% fee
    seller_payout = price - int(platform_fee)
    
    trade = CertMarketplaceTrade(
        seller_id=cert.user_id,
        buyer_id=current_user.id,
        cert_id=cert.id,
        trade_price=price,
        platform_fee=platform_fee,
        seller_payout=seller_payout,
        status='completed',
        completed_at=datetime.utcnow()
    )
    
    # Transfer certificate to buyer (create a copy for buyer)
    new_cert = UserCertification(
        user_id=current_user.id,
        template_id=cert.template_id,
        earned_at=datetime.utcnow(),
        is_verified=True
    )
    
    # Unlist original
    cert.for_sale = False
    cert.listing_price = None
    cert.template.active_listings -= 1
    
    # Award XP
    current_user.xp_points += 50
    seller.xp_points += 50
    
    # Update market stats
    cert.template.trend_24h = (cert.template.trend_24h + 1) % 100
    cert.template.last_sale_days_ago = 0
    
    db.session.add(trade)
    db.session.add(new_cert)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'Successfully purchased {cert.template.name}!',
        'trade': trade.to_dict(),
        'certificate': new_cert.to_dict()
    })


@marketplace_bp.route('/trades/history', methods=['GET'])
@token_required
def get_trade_history(current_user):
    """Get user's trade history (bought and sold)"""
    limit = request.args.get('limit', 50, type=int)
    
    # Get trades where user is buyer or seller
    trades = CertMarketplaceTrade.query.filter(
        (CertMarketplaceTrade.buyer_id == current_user.id) |
        (CertMarketplaceTrade.seller_id == current_user.id)
    ).order_by(CertMarketplaceTrade.created_at.desc()).limit(limit).all()
    
    return jsonify({
        'success': True,
        'trades': [trade.to_dict() for trade in trades],
        'total': len(trades)
    })


# ==================== ANALYTICS ====================

@marketplace_bp.route('/analytics/market-stats', methods=['GET'])
def get_market_stats():
    """Get overall marketplace statistics"""
    total_trades = CertMarketplaceTrade.query.count()
    completed_trades = CertMarketplaceTrade.query.filter_by(status='completed').count()
    
    total_volume = db.session.query(db.func.sum(CertMarketplaceTrade.trade_price)).filter_by(
        status='completed'
    ).scalar() or 0
    
    active_listings = db.session.query(db.func.count(UserCertification.id)).filter_by(
        for_sale=True
    ).scalar()
    
    total_certs = CertificationTemplate.query.count()
    
    return jsonify({
        'success': True,
        'market_volume': total_volume,
        'active_listings': active_listings,
        'completed_trades': completed_trades,
        'total_certificates': total_certs,
        'avg_trade_value': total_volume // completed_trades if completed_trades > 0 else 0
    })


@marketplace_bp.route('/analytics/certificate/<int:cert_id>/stats', methods=['GET'])
def get_certificate_stats(cert_id):
    """Get detailed statistics for a specific certificate"""
    cert = CertificationTemplate.query.get(cert_id)
    if not cert:
        return jsonify({'error': 'Certificate not found'}), 404
    
    # Get price history (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    trades = CertMarketplaceTrade.query.filter(
        CertMarketplaceTrade.cert_id == cert_id,
        CertMarketplaceTrade.status == 'completed',
        CertMarketplaceTrade.completed_at >= thirty_days_ago
    ).order_by(CertMarketplaceTrade.completed_at).all()
    
    prices = [trade.trade_price for trade in trades]
    
    stats = {
        'certificate': cert.to_dict(),
        'total_trades': len(trades),
        'avg_price': sum(prices) // len(prices) if prices else cert.base_price,
        'min_price': min(prices) if prices else cert.base_price,
        'max_price': max(prices) if prices else cert.base_price,
        'price_history': [
            {
                'date': trade.completed_at.isoformat(),
                'price': trade.trade_price
            }
            for trade in trades
        ]
    }
    
    return jsonify({'success': True, **stats})


@marketplace_bp.route('/analytics/trending', methods=['GET'])
def get_trending_certificates():
    """Get trending certifications based on volume and demand"""
    limit = request.args.get('limit', 10, type=int)
    
    # Sort by trend and active listings
    trending = CertificationTemplate.query.order_by(
        CertificationTemplate.trend_24h.desc(),
        CertificationTemplate.active_listings.desc()
    ).limit(limit).all()
    
    return jsonify({
        'success': True,
        'trending': [cert.to_dict() for cert in trending]
    })


# ==================== VERIFICATION ====================

@marketplace_bp.route('/verify/<int:cert_id>/employer', methods=['POST'])
def request_employer_verification(cert_id):
    """Request employer verification of a certificate"""
    data = request.get_json()
    employer_name = data.get('employer_name', '')
    employer_email = data.get('employer_email', '')
    employer_logo = data.get('employer_logo', '')
    
    cert = UserCertification.query.get(cert_id)
    if not cert:
        return jsonify({'error': 'Certificate not found'}), 404
    
    # Create verification request
    verification = EmployerVerification(
        employer_name=employer_name,
        employer_email=employer_email,
        employer_logo=employer_logo,
        cert_id=cert_id,
        verification_token=str(uuid.uuid4())
    )
    
    db.session.add(verification)
    db.session.commit()
    
    # TODO: Send verification email to employer
    
    return jsonify({
        'success': True,
        'message': 'Verification request sent to employer',
        'verification_id': verification.id
    })


@marketplace_bp.route('/verify/<int:cert_id>/verifications', methods=['GET'])
def get_certificate_verifications(cert_id):
    """Get all employer verifications for a certificate"""
    verifications = EmployerVerification.query.filter_by(cert_id=cert_id).all()
    
    return jsonify({
        'success': True,
        'verifications': [v.to_dict() for v in verifications],
        'total': len(verifications)
    })


import uuid
