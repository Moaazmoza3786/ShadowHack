"""
PHASE 4 Step 10: Deployment Preparation
- Dockerfile for containerization
- Docker Compose for multi-service orchestration
- CI/CD pipeline configuration (GitHub Actions)
- Environment configuration management
- Database migration scripts
"""

# This is a placeholder for deployment configuration files
# The actual files will be created as separate resources

DEPLOYMENT_FILES = {
    'Dockerfile': '''
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    postgresql-client \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY backend/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD python -c "import requests; requests.get('http://localhost:5000/health')"

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--worker-class", "sync", "--access-logfile", "-", "--error-logfile", "-", "main:app"]
''',
    
    'docker-compose.yml': '''
version: '3.8'

services:
  # Database service
  postgres:
    image: postgres:15-alpine
    container_name: shadowhack-db
    environment:
      POSTGRES_DB: ${DB_NAME:-shadowhack}
      POSTGRES_USER: ${DB_USER:-postgres}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-postgres}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backend/migrations/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "${DB_PORT:-5432}:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER:-postgres}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - shadowhack-network

  # Redis cache service
  redis:
    image: redis:7-alpine
    container_name: shadowhack-cache
    environment:
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    ports:
      - "${REDIS_PORT:-6379}:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - shadowhack-network

  # Backend API service
  backend:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: shadowhack-backend
    environment:
      - FLASK_ENV=${FLASK_ENV:-production}
      - DATABASE_URL=postgresql://${DB_USER:-postgres}:${DB_PASSWORD:-postgres}@postgres:5432/${DB_NAME:-shadowhack}
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - GROQ_API_KEY=${GROQ_API_KEY}
      - HACKERONE_API_KEY=${HACKERONE_API_KEY}
      - BUGCROWD_API_KEY=${BUGCROWD_API_KEY}
      - INTIGRITI_API_KEY=${INTIGRITI_API_KEY}
      - LINKEDIN_CLIENT_ID=${LINKEDIN_CLIENT_ID}
      - LINKEDIN_CLIENT_SECRET=${LINKEDIN_CLIENT_SECRET}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    ports:
      - "${BACKEND_PORT:-5000}:5000"
    volumes:
      - ./backend:/app
    networks:
      - shadowhack-network
    restart: unless-stopped

  # Frontend service (optional)
  frontend:
    build:
      context: ./study-hub-react
      dockerfile: Dockerfile
    container_name: shadowhack-frontend
    environment:
      - REACT_APP_API_URL=${BACKEND_URL:-http://backend:5000}
    ports:
      - "${FRONTEND_PORT:-3000}:3000"
    depends_on:
      - backend
    networks:
      - shadowhack-network
    restart: unless-stopped

  # Nginx reverse proxy (optional)
  nginx:
    image: nginx:alpine
    container_name: shadowhack-proxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - backend
      - frontend
    networks:
      - shadowhack-network
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:

networks:
  shadowhack-network:
    driver: bridge
''',

    '.github/workflows/ci-cd.yml': '''
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # Code Quality & Testing
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_DB: test_db
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          cache: 'pip'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r backend/requirements.txt
          pip install pytest pytest-cov pytest-xdist
      
      - name: Run linting
        run: |
          pip install flake8 pylint
          flake8 backend/ --count --select=E9,F63,F7,F82 --show-source --statistics
          flake8 backend/ --count --exit-zero --max-complexity=10
      
      - name: Run tests
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
          REDIS_URL: redis://localhost:6379/0
        run: |
          pytest backend/test_comprehensive.py -v --cov=backend --cov-report=xml --cov-report=html
      
      - name: Upload coverage reports
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
          fail_ci_if_error: false
      
      - name: Run security checks
        run: |
          pip install bandit safety
          bandit -r backend/ -f json -o bandit-report.json || true
          safety check --json || true

  # Build Docker image
  build:
    needs: test
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      packages: write
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2
      
      - name: Log in to registry
        uses: docker/login-action@v2
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Build and push image
        uses: docker/build-push-action@v4
        with:
          context: .
          push: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max

  # Deploy to staging
  deploy-staging:
    needs: build
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/develop'
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to staging
        env:
          DEPLOY_KEY: ${{ secrets.STAGING_DEPLOY_KEY }}
          DEPLOY_HOST: ${{ secrets.STAGING_HOST }}
        run: |
          mkdir -p ~/.ssh
          echo "${{ env.DEPLOY_KEY }}" > ~/.ssh/deploy_key
          chmod 600 ~/.ssh/deploy_key
          ssh-keyscan ${{ env.DEPLOY_HOST }} >> ~/.ssh/known_hosts
          ssh -i ~/.ssh/deploy_key deployer@${{ env.DEPLOY_HOST }} "cd /app && docker-compose pull && docker-compose up -d"

  # Deploy to production
  deploy-production:
    needs: build
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    environment: production
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to production
        env:
          DEPLOY_KEY: ${{ secrets.PROD_DEPLOY_KEY }}
          DEPLOY_HOST: ${{ secrets.PROD_HOST }}
        run: |
          mkdir -p ~/.ssh
          echo "${{ env.DEPLOY_KEY }}" > ~/.ssh/deploy_key
          chmod 600 ~/.ssh/deploy_key
          ssh-keyscan ${{ env.DEPLOY_HOST }} >> ~/.ssh/known_hosts
          ssh -i ~/.ssh/deploy_key deployer@${{ env.DEPLOY_HOST }} "cd /app && docker-compose pull && docker-compose up -d"
      
      - name: Slack notification
        if: always()
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: 'Production deployment ${{ job.status }}'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
''',

    '.env.example': '''
# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-super-secret-key-here-change-in-production

# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_NAME=shadowhack
DB_USER=postgres
DB_PASSWORD=change-this-password

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=change-this-password
REDIS_URL=redis://:change-this-password@redis:6379/0

# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# API Keys
GROQ_API_KEY=your-groq-api-key
HACKERONE_API_KEY=your-hackerone-api-key
BUGCROWD_API_KEY=your-bugcrowd-api-key
INTIGRITI_API_KEY=your-intigriti-api-key

# OAuth Configuration
LINKEDIN_CLIENT_ID=your-linkedin-client-id
LINKEDIN_CLIENT_SECRET=your-linkedin-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Email Configuration (for notifications)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# AWS S3 (for file uploads)
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_BUCKET_NAME=shadowhack-uploads
AWS_REGION=us-east-1

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/shadowhack/app.log

# URLs
BACKEND_URL=http://localhost:5000
FRONTEND_URL=http://localhost:3000
''',

    'backend/requirements.txt': '''
# Web Framework
Flask==3.0.0
Flask-CORS==4.0.0
Flask-SQLAlchemy==3.1.1
Flask-JWT-Extended==4.5.2
Werkzeug==3.0.0

# Database
SQLAlchemy==2.0.23
psycopg2-binary==2.9.9
alembic==1.13.0

# Caching & Task Queue
redis==5.0.1
RQ==1.15.1

# AI/ML Integration
groq==0.4.2
requests==2.31.0

# Security
cryptography==41.0.7
bcrypt==4.1.1
pyjwt==2.8.1

# Data Validation
pydantic==2.5.2
marshmallow==3.20.1

# Performance
gunicorn==21.2.0
gevent==23.9.1

# Testing
pytest==7.4.3
pytest-cov==4.1.0
pytest-xdist==3.5.0
pytest-flask==1.3.0
factory-boy==3.3.0

# Code Quality
flake8==6.1.0
pylint==3.0.3
black==23.12.0
isort==5.13.2

# Monitoring & Logging
python-dotenv==1.0.0
Loguru==0.7.2

# AWS SDK (optional)
boto3==1.34.0

# HTTP Client
aiohttp==3.9.1
httpx==0.25.2

# Utilities
python-dateutil==2.8.2
pytz==2023.3
click==8.1.7
''',

    'backend/migrations/init.sql': '''
-- Initialize database schema for ShadowHack

-- Users table
CREATE TABLE IF NOT EXISTS "user" (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    bio TEXT,
    avatar_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Courses table
CREATE TABLE IF NOT EXISTS course (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    difficulty VARCHAR(50),
    category VARCHAR(100),
    instructor_id INTEGER REFERENCES "user"(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Progress tracking
CREATE TABLE IF NOT EXISTS progress (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    course_id INTEGER NOT NULL REFERENCES course(id) ON DELETE CASCADE,
    percentage FLOAT DEFAULT 0,
    status VARCHAR(50) DEFAULT 'not_started',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, course_id)
);

-- Wiki articles
CREATE TABLE IF NOT EXISTS wiki_article (
    id SERIAL PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    content TEXT NOT NULL,
    category VARCHAR(100),
    author_id INTEGER NOT NULL REFERENCES "user"(id),
    views INTEGER DEFAULT 0,
    votes INTEGER DEFAULT 0,
    is_archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Game scores
CREATE TABLE IF NOT EXISTS game_score (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    game_id INTEGER,
    score INTEGER NOT NULL,
    difficulty VARCHAR(50),
    played_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bug bounty submissions
CREATE TABLE IF NOT EXISTS bug_bounty_submission (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user"(id),
    platform VARCHAR(100),
    program_name VARCHAR(255),
    title VARCHAR(255),
    description TEXT,
    severity VARCHAR(50),
    status VARCHAR(50),
    bounty_amount FLOAT,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_email ON "user"(email);
CREATE INDEX IF NOT EXISTS idx_user_username ON "user"(username);
CREATE INDEX IF NOT EXISTS idx_progress_user ON progress(user_id);
CREATE INDEX IF NOT EXISTS idx_progress_course ON progress(course_id);
CREATE INDEX IF NOT EXISTS idx_wiki_author ON wiki_article(author_id);
CREATE INDEX IF NOT EXISTS idx_wiki_category ON wiki_article(category);
CREATE INDEX IF NOT EXISTS idx_game_user ON game_score(user_id);
CREATE INDEX IF NOT EXISTS idx_bounty_user ON bug_bounty_submission(user_id);
CREATE INDEX IF NOT EXISTS idx_bounty_platform ON bug_bounty_submission(platform);
''',

    'docker/.dockerignore': '''
__pycache__
*.pyc
*.pyo
*.pyd
.Python
env/
venv/
.venv
.git
.gitignore
.env
.env.local
.DS_Store
*.db
*.sqlite
node_modules/
.pytest_cache
.coverage
htmlcov/
dist/
build/
*.egg-info/
.idea/
.vscode/
*.log
''',

    'docker/nginx.conf': '''
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 20M;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/atom+xml image/svg+xml;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;

    upstream backend {
        server backend:5000;
    }

    upstream frontend {
        server frontend:3000;
    }

    server {
        listen 80;
        server_name _;

        # Redirect HTTP to HTTPS (in production)
        # return 301 https://$server_name$request_uri;

        # API endpoints
        location /api/ {
            limit_req zone=api burst=50 nodelay;
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 30s;
        }

        # Static files and frontend
        location / {
            limit_req zone=general burst=20 nodelay;
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Health check
        location /health {
            access_log off;
            return 200 "healthy\\n";
            add_header Content-Type text/plain;
        }
    }
}
'''
}


class DeploymentManager:
    """Manager for deployment configuration and scripts"""
    
    @staticmethod
    def get_deployment_checklist():
        """Get pre-deployment checklist"""
        return {
            'Pre-Deployment': [
                '✓ All tests passing (unit, integration, security)',
                '✓ Code review completed',
                '✓ Database migrations tested',
                '✓ Environment variables configured',
                '✓ SSL certificates generated/obtained',
                '✓ API keys and secrets added to CI/CD secrets',
                '✓ Backup strategy in place',
                '✓ Monitoring and alerting configured'
            ],
            'Deployment': [
                '✓ Docker images built and pushed to registry',
                '✓ Database migrations applied',
                '✓ Environment variables set on server',
                '✓ Docker Compose configuration deployed',
                '✓ Services started and health checks passing',
                '✓ DNS/load balancer updated (if needed)',
                '✓ SSL certificates configured',
                '✓ Monitoring dashboards accessible'
            ],
            'Post-Deployment': [
                '✓ Smoke tests run (basic functionality)',
                '✓ API endpoints responding',
                '✓ Database connectivity verified',
                '✓ Redis cache working',
                '✓ Logs being collected',
                '✓ Monitoring alerts active',
                '✓ Performance metrics normal',
                '✓ Security scans passed'
            ],
            'Rollback Plan': [
                '✓ Previous version tagged in Docker registry',
                '✓ Database rollback procedure documented',
                '✓ Rollback command tested',
                '✓ Communication plan for rollback'
            ]
        }
    
    @staticmethod
    def get_deployment_script():
        """Get deployment script"""
        return '''#!/bin/bash

set -e

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

echo "${YELLOW}=== ShadowHack Deployment Script ===${NC}"

# Check prerequisites
echo "${YELLOW}Checking prerequisites...${NC}"
command -v docker >/dev/null 2>&1 || { echo "${RED}Docker is required${NC}"; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "${RED}Docker Compose is required${NC}"; exit 1; }

# Load environment variables
if [ ! -f .env ]; then
    echo "${RED}Error: .env file not found${NC}"
    exit 1
fi

echo "${GREEN}✓ Prerequisites met${NC}"

# Build Docker images
echo "${YELLOW}Building Docker images...${NC}"
docker-compose build

echo "${GREEN}✓ Docker images built${NC}"

# Run database migrations
echo "${YELLOW}Running database migrations...${NC}"
docker-compose run --rm backend flask db upgrade

echo "${GREEN}✓ Database migrations completed${NC}"

# Start services
echo "${YELLOW}Starting services...${NC}"
docker-compose up -d

echo "${GREEN}✓ Services started${NC}"

# Wait for services to be healthy
echo "${YELLOW}Waiting for services to be healthy...${NC}"
sleep 10

# Check service health
echo "${YELLOW}Checking service health...${NC}"

# Check database
if docker exec shadowhack-db pg_isready -U postgres > /dev/null; then
    echo "${GREEN}✓ Database is healthy${NC}"
else
    echo "${RED}✗ Database health check failed${NC}"
    exit 1
fi

# Check Redis
if docker exec shadowhack-cache redis-cli ping > /dev/null; then
    echo "${GREEN}✓ Redis is healthy${NC}"
else
    echo "${RED}✗ Redis health check failed${NC}"
    exit 1
fi

# Check backend
if curl -f http://localhost:5000/health > /dev/null; then
    echo "${GREEN}✓ Backend is healthy${NC}"
else
    echo "${RED}✗ Backend health check failed${NC}"
    exit 1
fi

echo "${GREEN}=== Deployment Successful ===${NC}"
echo "${YELLOW}Services available at:${NC}"
echo "  Backend API: http://localhost:5000"
echo "  Frontend: http://localhost:3000"
echo "  Database: localhost:5432"
echo "  Redis: localhost:6379"
'''
    
    @staticmethod
    def get_monitoring_stack():
        """Get monitoring stack configuration"""
        return {
            'prometheus.yml': '''
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'shadowhack-backend'
    static_configs:
      - targets: ['backend:5000']
    metrics_path: '/metrics'

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres_exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis_exporter:9121']
''',
            
            'alerting-rules.yml': '''
groups:
  - name: shadowhack
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High error rate detected"
      
      - alert: DatabaseConnectionFailure
        expr: pg_up == 0
        for: 1m
        annotations:
          summary: "Database connection lost"
      
      - alert: HighMemoryUsage
        expr: container_memory_usage_bytes / 1e9 > 4
        for: 5m
        annotations:
          summary: "High memory usage"
      
      - alert: DiskSpaceRunningOut
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.1
        for: 5m
        annotations:
          summary: "Disk space running out"
'''
        }


def print_deployment_guide():
    """Print deployment guide"""
    guide = """
╔═══════════════════════════════════════════════════════════════╗
║           PHASE 4 STEP 10: DEPLOYMENT GUIDE                  ║
╚═══════════════════════════════════════════════════════════════╝

1. PREPARE ENVIRONMENT
   - Copy .env.example to .env
   - Update all environment variables for production
   - Ensure database credentials are strong
   - Generate JWT_SECRET_KEY: openssl rand -hex 32

2. BUILD DOCKER IMAGES
   docker-compose build

3. INITIALIZE DATABASE
   docker-compose run --rm backend flask db upgrade

4. START SERVICES
   docker-compose up -d

5. VERIFY DEPLOYMENT
   docker-compose ps                    # Check all services
   docker-compose logs backend          # Check logs
   curl http://localhost:5000/health    # Test API

6. CONFIGURE MONITORING
   - Set up Prometheus for metrics collection
   - Configure Grafana dashboards
   - Set up alerting rules
   - Configure log aggregation (ELK, Datadog, etc.)

7. BACKUP STRATEGY
   - Database: Daily backups to S3
   - Redis: Persistence enabled
   - Application code: Git-based versioning

8. SCALING
   - Horizontal: Use load balancer with multiple backend instances
   - Vertical: Increase container resource limits
   - Cache: Redis for frequently accessed data
   - Database: Read replicas for read-heavy workloads

9. CONTINUOUS DEPLOYMENT
   - Enable GitHub Actions for automated testing
   - Configure auto-deploy on main branch
   - Set up staging environment for testing
   - Implement blue-green deployment strategy

10. SECURITY HARDENING
    - Enable HTTPS with SSL/TLS certificates
    - Configure firewall rules
    - Set up WAF (Web Application Firewall)
    - Regular security audits and penetration testing

USEFUL COMMANDS:

View logs:
  docker-compose logs -f backend
  docker-compose logs -f postgres
  docker-compose logs -f redis

Stop services:
  docker-compose down

Remove volumes (WARNING: data loss):
  docker-compose down -v

Restart service:
  docker-compose restart backend

Execute command in container:
  docker-compose exec backend python -c "from app import app; print(app.config)"

Database backup:
  docker exec shadowhack-db pg_dump -U postgres shadowhack > backup.sql

Database restore:
  docker exec -i shadowhack-db psql -U postgres shadowhack < backup.sql

For more details, see deployment documentation.
"""
    print(guide)


if __name__ == '__main__':
    print_deployment_guide()
