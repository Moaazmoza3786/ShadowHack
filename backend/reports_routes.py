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

from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from flask import send_file

@reports_bp.route('/<int:report_id>/export', methods=['GET'])
def export_report_pdf(report_id):
    """
    Export report as PDF using ReportLab
    """
    report = Report.query.get_or_404(report_id)
    findings = report.findings.all()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # --- Title Page ---
    title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=24, spaceAfter=20)
    story.append(Paragraph("SECURITY ASSESSMENT REPORT", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Title: {report.title}", styles['Heading2']))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", styles['Normal']))
    story.append(Spacer(1, 30))
    story.append(Paragraph("CONFIDENTIAL", styles['Heading3']))
    story.append(Spacer(1, 50))

    # --- Executive Summary ---
    story.append(Paragraph("Executive Summary", styles['Heading1']))
    story.append(Paragraph(report.executive_summary or "No summary provided.", styles['Normal']))
    story.append(Spacer(1, 20))

    # --- Findings Summary Table ---
    story.append(Paragraph("Findings Summary", styles['Heading2']))
    data = [['Title', 'Severity', 'Status']]
    for f in findings:
        data.append([f.title, f.severity, 'Open'])

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))

    # --- Detailed Findings ---
    story.append(Paragraph("Detailed Findings", styles['Heading1']))
    for f in findings:
        # Severity Color
        sev_color = colors.black
        if f.severity == 'Critical': sev_color = colors.red
        elif f.severity == 'High': sev_color = colors.orange
        elif f.severity == 'Medium': sev_color = colors.yellow

        story.append(Paragraph(f"Finding: {f.title}", styles['Heading2']))
        story.append(Paragraph(f"Severity: <font color='{sev_color}'>{f.severity}</font>", styles['Normal']))
        story.append(Spacer(1, 6))
        
        story.append(Paragraph("Description:", styles['Heading3']))
        story.append(Paragraph(f.description or "N/A", styles['Normal']))
        story.append(Spacer(1, 6))

        story.append(Paragraph("Remediation:", styles['Heading3']))
        story.append(Paragraph(f.remediation or "N/A", styles['Normal']))
        story.append(Spacer(1, 12))
        story.append(Paragraph("-" * 60, styles['Normal']))
        story.append(Spacer(1, 12))

    doc.build(story)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'Security_Report_{report_id}.pdf',
        mimetype='application/pdf'
    )


def register_report_routes(app):
    """Register reports blueprint"""
    app.register_blueprint(reports_bp)
    print("✓ Report Routes: REGISTERED")
