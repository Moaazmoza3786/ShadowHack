"""
Report Routes for ShadowHack Platform
Phase 17: Reporting Tools
"""

from flask import Blueprint, request, jsonify
from models import db, Report, Finding, User
from datetime import datetime

reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')

@reports_bp.route('/', methods=['GET'])
def get_reports():
    """List user reports"""
    user_id = request.args.get('user_id', type=int)
    if not user_id:
        return jsonify({'success': False, 'error': 'User ID required'}), 400
        
    reports = Report.query.filter_by(user_id=user_id).order_by(Report.updated_at.desc()).all()
    return jsonify({
        'success': True,
        'reports': [r.to_dict() for r in reports]
    })

@reports_bp.route('/create', methods=['POST'])
def create_report():
    """Create new report draft"""
    data = request.json
    user_id = data.get('user_id')
    title = data.get('title', 'Untitled Security Report')
    lab_id = data.get('lab_id')
    
    report = Report(user_id=user_id, title=title, lab_id=lab_id)
    db.session.add(report)
    db.session.commit()
    
    return jsonify({'success': True, 'report': report.to_dict()})

@reports_bp.route('/<int:report_id>', methods=['GET'])
def get_report_detail(report_id):
    """Get full report with findings"""
    report = Report.query.get_or_404(report_id)
    findings = [f.to_dict() for f in report.findings.all()]
    
    data = report.to_dict()
    data['findings'] = findings
    data['executive_summary'] = report.executive_summary
    
    return jsonify({'success': True, 'report': data})

@reports_bp.route('/<int:report_id>/findings', methods=['POST'])
def add_finding(report_id):
    """Add finding to report"""
    report = Report.query.get_or_404(report_id)
    data = request.json
    
    finding = Finding(
        report_id=report.id,
        title=data.get('title'),
        severity=data.get('severity'),
        description=data.get('description'),
        remediation=data.get('remediation'),
        evidence=data.get('evidence')
    )
    
    db.session.add(finding)
    db.session.commit()
    
    return jsonify({'success': True, 'finding': finding.to_dict()})

@reports_bp.route('/<int:report_id>/export', methods=['GET'])
def export_report_pdf(report_id):
    """
    Export report as PDF
    Note: In a real environment, this would use WeasyPrint or pdfkit.
    For now, we return a mock success or HTML content.
    """
    # mock implementation
    return jsonify({
        'success': True, 
        'message': 'PDF generation simulation successful. Check download folder.'
    })


def register_report_routes(app):
    """Register reports blueprint"""
    app.register_blueprint(reports_bp)
    print("✓ Report Routes: REGISTERED")
