/**
 * CI/CD INTEGRATION SERVICE
 * GitHub Actions, GitLab CI, Jenkins, CircleCI, etc.
 */

const db = require('../config/database');
const { logger } = require('../utils/error-handler');

class CICDIntegrationService {
  constructor() {
    this.supportedPlatforms = ['github', 'gitlab', 'jenkins', 'circleci', 'azure-devops'];
  }

  /**
   * Générer configuration GitHub Actions
   */
  generateGitHubActionsConfig(options = {}) {
    const {
      scanOnPush = true,
      scanOnPR = true,
      failOnCritical = true,
      domains = [],
      schedule = '0 2 * * *' // Daily at 2 AM
    } = options;

    return `name: NEXUS Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '${schedule}'
  workflow_dispatch:

jobs:
  nexus-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Run NEXUS Security Scan
        uses: nexus-security/scan-action@v1
        with:
          api-key: \${{ secrets.NEXUS_API_KEY }}
          domains: '${domains.join(',')}'
          fail-on-critical: ${failOnCritical}
          
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: nexus-scan-results
          path: nexus-results.json
          
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('nexus-results.json'));
            const critical = results.vulnerabilities.filter(v => v.severity === 'critical').length;
            const high = results.vulnerabilities.filter(v => v.severity === 'high').length;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: \`## 🔍 NEXUS Security Scan Results
              
**Critical:** \${critical} | **High:** \${high}

\${critical > 0 ? '❌ Critical vulnerabilities must be fixed before merge' : '✅ No critical vulnerabilities'}

[View full report](https://app.nexus.security)
              \`
            });
`;
  }

  /**
   * Générer configuration GitLab CI
   */
  generateGitLabCIConfig(options = {}) {
    const {
      stage = 'security',
      allowFailure = false,
      domains = []
    } = options;

    return `# NEXUS Security Scan
nexus-scan:
  stage: ${stage}
  image: nexus-security/scanner:latest
  
  variables:
    NEXUS_API_KEY: $NEXUS_API_KEY
    NEXUS_DOMAINS: "${domains.join(',')}"
  
  script:
    - nexus-cli scan --domains $NEXUS_DOMAINS --format json --output nexus-results.json
    - |
      CRITICAL=$(jq '[.vulnerabilities[] | select(.severity=="critical")] | length' nexus-results.json)
      if [ $CRITICAL -gt 0 ]; then
        echo "❌ $CRITICAL critical vulnerabilities found"
        exit 1
      fi
      echo "✅ No critical vulnerabilities"
  
  artifacts:
    reports:
      junit: nexus-results.xml
    paths:
      - nexus-results.json
    expire_in: 30 days
  
  allow_failure: ${allowFailure}
  
  only:
    - merge_requests
    - main
`;
  }

  /**
   * Générer configuration Jenkins Pipeline
   */
  generateJenkinsConfig(options = {}) {
    const {
      domains = [],
      notifySlack = false,
      slackChannel = '#security'
    } = options;

    return `pipeline {
    agent any
    
    environment {
        NEXUS_API_KEY = credentials('nexus-api-key')
        NEXUS_DOMAINS = '${domains.join(',')}'
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    sh '''
                        nexus-cli scan \\
                            --domains $NEXUS_DOMAINS \\
                            --format json \\
                            --output nexus-results.json
                    '''
                    
                    def results = readJSON file: 'nexus-results.json'
                    def critical = results.vulnerabilities.findAll { it.severity == 'critical' }.size()
                    def high = results.vulnerabilities.findAll { it.severity == 'high' }.size()
                    
                    if (critical > 0) {
                        error("❌ Found \${critical} critical vulnerabilities")
                    }
                    
                    echo "✅ Security scan passed: 0 critical, \${high} high"
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'nexus-results.json', fingerprint: true
        }
        ${notifySlack ? `
        failure {
            slackSend(
                channel: '${slackChannel}',
                color: 'danger',
                message: "Security scan failed: \${env.JOB_NAME} #\${env.BUILD_NUMBER}"
            )
        }
        ` : ''}
    }
}`;
  }

  /**
   * Générer configuration CircleCI
   */
  generateCircleCIConfig(options = {}) {
    const { domains = [] } = options;

    return `version: 2.1

orbs:
  nexus: nexus-security/nexus@1.0.0

workflows:
  security-check:
    jobs:
      - nexus/scan:
          api-key: \$NEXUS_API_KEY
          domains: "${domains.join(',')}"
          fail-on-critical: true
          context: security-scanning
`;
  }

  /**
   * Générer CLI commands pour integration manuelle
   */
  generateCLICommands(options = {}) {
    const {
      apiKey = 'YOUR_API_KEY',
      domain = 'example.com',
      format = 'json'
    } = options;

    return {
      install: 'npm install -g @nexus-security/cli',
      
      scan: `nexus-cli scan \\
  --api-key ${apiKey} \\
  --domain ${domain} \\
  --format ${format} \\
  --output scan-results.${format}`,
      
      check_results: `# Check for critical vulnerabilities
CRITICAL=$(jq '[.vulnerabilities[] | select(.severity=="critical")] | length' scan-results.json)
if [ $CRITICAL -gt 0 ]; then
  echo "❌ Found $CRITICAL critical vulnerabilities"
  exit 1
fi
echo "✅ No critical vulnerabilities"`,
      
      upload_results: `# Upload results to artifact storage
curl -X POST https://api.nexus.security/v1/results \\
  -H "Authorization: Bearer ${apiKey}" \\
  -F "file=@scan-results.json"`
    };
  }

  /**
   * Générer badge markdown pour README
   */
  generateSecurityBadge(userId) {
    const score = this.getLatestScore(userId);
    
    const color = score >= 900 ? 'brightgreen' :
                 score >= 750 ? 'green' :
                 score >= 500 ? 'yellow' :
                 score >= 250 ? 'orange' : 'red';
    
    return {
      markdown: `[![NEXUS Security](https://img.shields.io/badge/security-${score}%2F1000-${color}?logo=security&style=flat-square)](https://nexus.security)`,
      html: `<img src="https://img.shields.io/badge/security-${score}%2F1000-${color}?logo=security&style=flat-square" alt="NEXUS Security Score" />`,
      score
    };
  }

  /**
   * Webhook handler pour CI/CD events
   */
  async handleCIWebhook(payload, platform) {
    logger.logInfo('CI/CD webhook received', { platform });
    
    const event = this.parseCIEvent(payload, platform);
    
    // Déclencher scan si nécessaire
    if (event.shouldScan) {
      return await this.triggerAutomatedScan(event);
    }
    
    return { processed: true, action: 'none' };
  }

  /**
   * Parser événement CI/CD
   */
  parseCIEvent(payload, platform) {
    switch (platform) {
      case 'github':
        return {
          type: payload.action || 'push',
          branch: payload.ref?.replace('refs/heads/', ''),
          commit: payload.after || payload.pull_request?.head?.sha,
          shouldScan: payload.action === 'opened' || payload.action === 'synchronize' || payload.ref?.includes('main')
        };
      
      case 'gitlab':
        return {
          type: payload.object_kind,
          branch: payload.ref?.replace('refs/heads/', ''),
          commit: payload.checkout_sha,
          shouldScan: payload.object_kind === 'push' || payload.object_kind === 'merge_request'
        };
      
      default:
        return { shouldScan: false };
    }
  }

  /**
   * Déclencher scan automatique
   */
  async triggerAutomatedScan(event) {
    logger.logInfo('Triggering automated scan', event);
    
    // Ici on déclencherait un vrai scan
    // Pour l'instant simulation
    
    return {
      scan_id: `AUTO-${Date.now()}`,
      status: 'queued',
      estimated_time: '2 minutes',
      webhook_url: '/api/scans/webhook'
    };
  }

  /**
   * Obtenir le dernier score
   */
  getLatestScore(userId) {
    try {
      const scoreService = require('./security-health-score');
      const score = scoreService.calculateUserScore(userId);
      return score.score;
    } catch (error) {
      return 500; // Default
    }
  }

  /**
   * Générer documentation d'intégration
   */
  generateIntegrationDocs(platform, userConfig) {
    const configs = {
      github: this.generateGitHubActionsConfig(userConfig),
      gitlab: this.generateGitLabCIConfig(userConfig),
      jenkins: this.generateJenkinsConfig(userConfig),
      circleci: this.generateCircleCIConfig(userConfig)
    };

    const steps = {
      github: [
        '1. Create .github/workflows/nexus-security.yml',
        '2. Add NEXUS_API_KEY to repository secrets',
        '3. Commit and push to trigger scan',
        '4. View results in Actions tab'
      ],
      gitlab: [
        '1. Add configuration to .gitlab-ci.yml',
        '2. Set NEXUS_API_KEY in CI/CD variables',
        '3. Run pipeline to trigger scan',
        '4. View results in Pipelines'
      ],
      jenkins: [
        '1. Create Jenkinsfile in repository',
        '2. Add nexus-api-key credential',
        '3. Create pipeline job',
        '4. Run build to trigger scan'
      ],
      circleci: [
        '1. Create .circleci/config.yml',
        '2. Add NEXUS_API_KEY to environment',
        '3. Commit to trigger workflow',
        '4. View results in CircleCI dashboard'
      ]
    };

    return {
      platform,
      configuration: configs[platform] || '',
      setup_steps: steps[platform] || [],
      documentation_url: `https://docs.nexus.security/integrations/${platform}`,
      support_url: 'https://support.nexus.security'
    };
  }
}

module.exports = new CICDIntegrationService();
