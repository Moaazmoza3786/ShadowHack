"""
Pre-built Workflow Templates for common penetration testing scenarios
"""

from workflows import (
    WorkflowTemplate, WorkflowStep, WorkflowInput, 
    get_workflow_engine, datetime
)


def create_web_penetration_template() -> WorkflowTemplate:
    """Web Application Penetration Testing workflow"""
    return WorkflowTemplate(
        id="web-pentest",
        name="Web Application Penetration Testing",
        description="Comprehensive web app security assessment",
        category="web",
        difficulty="intermediate",
        version="1.0.0",
        author="ShadowHack Elite",
        icon="🌐",
        estimated_time=120,
        inputs=[
            WorkflowInput(
                name="target_url",
                type="string",
                required=True,
                description="Target web application URL"
            ),
            WorkflowInput(
                name="scan_depth",
                type="select",
                required=True,
                default="medium",
                options=["light", "medium", "deep"],
                description="Scanning depth level"
            )
        ],
        steps=[
            WorkflowStep(
                id="step-1-reconnaissance",
                type="action",
                name="Reconnaissance",
                description="Gather information about target",
                action="nmap_scan",
                inputs={"target": "${target_url}"},
                timeout=300
            ),
            WorkflowStep(
                id="step-2-domain-enum",
                type="action",
                name="Domain Enumeration",
                description="Enumerate subdomains",
                action="subdomain_enum",
                inputs={"domain": "${target_url}"},
                timeout=600
            ),
            WorkflowStep(
                id="step-3-web-crawl",
                type="action",
                name="Web Application Crawling",
                description="Crawl website structure",
                action="burp_crawl",
                inputs={"url": "${target_url}", "depth": "${scan_depth}"},
                timeout=900
            ),
            WorkflowStep(
                id="step-4-vuln-scan",
                type="action",
                name="Vulnerability Scanning",
                description="Scan for common vulnerabilities",
                action="nikto_scan",
                inputs={"target": "${target_url}"},
                timeout=1800
            ),
            WorkflowStep(
                id="step-5-sql-injection",
                type="action",
                name="SQL Injection Testing",
                description="Test for SQL injection vulnerabilities",
                action="sqlmap_test",
                inputs={"url": "${target_url}"},
                timeout=600
            ),
            WorkflowStep(
                id="step-6-report-gen",
                type="action",
                name="Generate Report",
                description="Compile findings into report",
                action="generate_report",
                inputs={"findings": "${results}"},
                timeout=300
            )
        ],
        tags=["web", "comprehensive", "intermediate"],
        best_practices=[
            "Always obtain written permission before testing",
            "Start with reconnaissance to understand the target",
            "Use moderate aggressiveness to avoid impact",
            "Document all findings with PoC",
            "Test both authentication and authorization",
            "Check for sensitive data exposure",
            "Test for common OWASP Top 10"
        ],
        expected_output="Comprehensive penetration test report with findings and remediation steps",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat()
    )


def create_network_reconnaissance_template() -> WorkflowTemplate:
    """Network Reconnaissance workflow"""
    return WorkflowTemplate(
        id="network-recon",
        name="Network Reconnaissance",
        description="Network discovery and enumeration",
        category="network",
        difficulty="beginner",
        version="1.0.0",
        author="ShadowHack Elite",
        icon="🌍",
        estimated_time=60,
        inputs=[
            WorkflowInput(
                name="target_network",
                type="string",
                required=True,
                description="Target network (CIDR notation, e.g., 192.168.1.0/24)"
            ),
            WorkflowInput(
                name="aggressive",
                type="boolean",
                required=False,
                default=False,
                description="Use aggressive scanning"
            )
        ],
        steps=[
            WorkflowStep(
                id="step-1-ping-sweep",
                type="action",
                name="Ping Sweep",
                description="Identify live hosts",
                action="ping_sweep",
                inputs={"network": "${target_network}"},
                timeout=300
            ),
            WorkflowStep(
                id="step-2-port-scan",
                type="action",
                name="Port Scanning",
                description="Scan open ports on live hosts",
                action="nmap_ports",
                inputs={"network": "${target_network}", "aggressive": "${aggressive}"},
                timeout=1200
            ),
            WorkflowStep(
                id="step-3-service-enum",
                type="action",
                name="Service Enumeration",
                description="Identify running services",
                action="service_enum",
                inputs={"targets": "${results}"},
                timeout=600
            ),
            WorkflowStep(
                id="step-4-os-detect",
                type="action",
                name="OS Detection",
                description="Detect operating systems",
                action="os_detect",
                inputs={"targets": "${results}"},
                timeout=600
            )
        ],
        tags=["network", "reconnaissance", "beginner"],
        best_practices=[
            "Always have network owner permission",
            "Start with light scans to assess network",
            "Use ping sweep before intensive scanning",
            "Document all discovered assets",
            "Check for unexpected services",
            "Note unusual configurations",
            "Map the network topology"
        ],
        expected_output="Network map with discovered hosts, open ports, and running services",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat()
    )


def create_mobile_security_template() -> WorkflowTemplate:
    """Mobile Application Security Testing workflow"""
    return WorkflowTemplate(
        id="mobile-security",
        name="Mobile Security Testing",
        description="Android and iOS security assessment",
        category="mobile",
        difficulty="advanced",
        version="1.0.0",
        author="ShadowHack Elite",
        icon="📱",
        estimated_time=180,
        inputs=[
            WorkflowInput(
                name="app_package",
                type="string",
                required=True,
                description="App package name or bundle identifier"
            ),
            WorkflowInput(
                name="platform",
                type="select",
                required=True,
                options=["android", "ios"],
                description="Target platform"
            ),
            WorkflowInput(
                name="test_scope",
                type="string",
                required=True,
                description="Components to test (comma-separated)"
            )
        ],
        steps=[
            WorkflowStep(
                id="step-1-setup",
                type="action",
                name="Environment Setup",
                description="Setup testing environment",
                action="setup_mobile_env",
                inputs={"platform": "${platform}"},
                timeout=600
            ),
            WorkflowStep(
                id="step-2-app-extract",
                type="action",
                name="Extract APK/IPA",
                description="Extract and analyze application package",
                action="extract_app",
                inputs={"package": "${app_package}", "platform": "${platform}"},
                timeout=300
            ),
            WorkflowStep(
                id="step-3-static-analysis",
                type="action",
                name="Static Code Analysis",
                description="Analyze source code for vulnerabilities",
                action="static_analysis_mobile",
                inputs={"app": "${app_package}"},
                timeout=900
            ),
            WorkflowStep(
                id="step-4-dynamic-analysis",
                type="action",
                name="Dynamic Testing",
                description="Runtime behavior analysis",
                action="dynamic_analysis_mobile",
                inputs={"app": "${app_package}"},
                timeout=1200
            ),
            WorkflowStep(
                id="step-5-api-testing",
                type="action",
                name="API Security Testing",
                description="Test mobile API calls",
                action="test_mobile_api",
                inputs={"app": "${app_package}"},
                timeout=600
            ),
            WorkflowStep(
                id="step-6-data-storage",
                type="action",
                name="Data Storage Analysis",
                description="Check for insecure data storage",
                action="analyze_storage",
                inputs={"app": "${app_package}"},
                timeout=300
            )
        ],
        tags=["mobile", "android", "ios", "advanced"],
        best_practices=[
            "Test on real devices when possible",
            "Check OWASP Mobile Top 10",
            "Test both authentication and authorization",
            "Analyze encrypted data storage",
            "Test API endpoints for security",
            "Check for hardcoded credentials",
            "Test for insecure network communications",
            "Check for code obfuscation"
        ],
        expected_output="Mobile app security assessment with findings and remediation",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat()
    )


def create_cloud_assessment_template() -> WorkflowTemplate:
    """Cloud Infrastructure Security Assessment"""
    return WorkflowTemplate(
        id="cloud-assessment",
        name="Cloud Infrastructure Assessment",
        description="AWS, Azure, GCP security testing",
        category="cloud",
        difficulty="advanced",
        version="1.0.0",
        author="ShadowHack Elite",
        icon="☁️",
        estimated_time=240,
        inputs=[
            WorkflowInput(
                name="cloud_provider",
                type="select",
                required=True,
                options=["aws", "azure", "gcp"],
                description="Cloud provider"
            ),
            WorkflowInput(
                name="credentials_type",
                type="select",
                required=True,
                options=["api_keys", "service_account", "cli_profile"],
                description="Authentication method"
            ),
            WorkflowInput(
                name="scope",
                type="string",
                required=True,
                description="Resources to assess (e.g., specific VPC, tenant)"
            )
        ],
        steps=[
            WorkflowStep(
                id="step-1-auth-validate",
                type="action",
                name="Validate Credentials",
                description="Verify cloud credentials",
                action="validate_cloud_creds",
                inputs={"provider": "${cloud_provider}"},
                timeout=300
            ),
            WorkflowStep(
                id="step-2-inventory",
                type="action",
                name="Asset Discovery",
                description="Enumerate cloud resources",
                action="cloud_inventory",
                inputs={"provider": "${cloud_provider}", "scope": "${scope}"},
                timeout=600
            ),
            WorkflowStep(
                id="step-3-iam-audit",
                type="action",
                name="IAM Audit",
                description="Analyze IAM policies and permissions",
                action="iam_audit",
                inputs={"provider": "${cloud_provider}"},
                timeout=600
            ),
            WorkflowStep(
                id="step-4-network-check",
                type="action",
                name="Network Security Check",
                description="Assess network configurations",
                action="cloud_network_check",
                inputs={"provider": "${cloud_provider}", "scope": "${scope}"},
                timeout=600
            ),
            WorkflowStep(
                id="step-5-storage-audit",
                type="action",
                name="Storage Security Audit",
                description="Check data storage configurations",
                action="cloud_storage_audit",
                inputs={"provider": "${cloud_provider}"},
                timeout=600
            ),
            WorkflowStep(
                id="step-6-encryption-check",
                type="action",
                name="Encryption Verification",
                description="Verify encryption settings",
                action="verify_encryption",
                inputs={"provider": "${cloud_provider}"},
                timeout=300
            )
        ],
        tags=["cloud", "aws", "azure", "gcp", "advanced"],
        best_practices=[
            "Always have cloud account owner permission",
            "Test in non-production environments first",
            "Review IAM policies thoroughly",
            "Check for public resource exposure",
            "Verify encryption at rest and transit",
            "Test multi-factor authentication",
            "Review audit logging configuration",
            "Check for least privilege violations"
        ],
        expected_output="Cloud security assessment with identified misconfigurations and risks",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat()
    )


def create_quick_assessment_template() -> WorkflowTemplate:
    """Quick Security Assessment for rapid scanning"""
    return WorkflowTemplate(
        id="quick-assessment",
        name="Quick Security Assessment",
        description="Fast security scan for rapid findings",
        category="general",
        difficulty="beginner",
        version="1.0.0",
        author="ShadowHack Elite",
        icon="⚡",
        estimated_time=30,
        inputs=[
            WorkflowInput(
                name="target",
                type="string",
                required=True,
                description="Target URL or IP address"
            )
        ],
        steps=[
            WorkflowStep(
                id="step-1-quick-scan",
                type="action",
                name="Quick Port Scan",
                description="Fast port scan",
                action="quick_nmap",
                inputs={"target": "${target}"},
                timeout=180
            ),
            WorkflowStep(
                id="step-2-quick-web",
                type="action",
                name="Quick Web Scan",
                description="Fast web vulnerability scan",
                action="quick_web_scan",
                inputs={"target": "${target}"},
                timeout=300
            ),
            WorkflowStep(
                id="step-3-quick-report",
                type="action",
                name="Generate Quick Report",
                description="Create quick findings report",
                action="quick_report",
                inputs={"findings": "${results}"},
                timeout=60
            )
        ],
        tags=["quick", "fast", "beginner", "automation"],
        best_practices=[
            "Use for quick security checks",
            "Follow up with detailed assessment",
            "Good for initial scoping",
            "Use standard port ranges"
        ],
        expected_output="Quick report with high-priority findings",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat()
    )


def register_default_templates() -> None:
    """Register all default workflow templates"""
    engine = get_workflow_engine()
    
    templates = [
        create_web_penetration_template(),
        create_network_reconnaissance_template(),
        create_mobile_security_template(),
        create_cloud_assessment_template(),
        create_quick_assessment_template()
    ]
    
    for template in templates:
        try:
            engine.register_template(template)
            print(f"✓ Registered template: {template.name}")
        except ValueError as e:
            print(f"✗ Error registering template {template.id}: {e}")
