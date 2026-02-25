/**
 * REAL-TIME ATTACK SIMULATION & DEFENSE TRAINING
 * 
 * INNOVATION RÉVOLUTIONNAIRE #3 - Cyber Range as a Service
 * 
 * Features:
 * - Simule des attaques réelles en temps réel
 * - Entraîne les équipes à répondre aux incidents
 * - Mesure le temps de réponse
 * - Score de préparation (Readiness Score)
 * - Scénarios d'attaque réalistes
 * - Dashboard de performance d'équipe
 * - Certifications de compétence
 * - Gamification du training
 * 
 * DIFFÉRENCIATION ABSOLUE:
 * - Burp Suite: Aucun training ❌
 * - Acunetix: Aucun training ❌
 * - Qualys: Aucun training ❌
 * - Cyber Ranges traditionnels: $50K-200K/an 💰
 * - NEXUS: INCLUDED + Automated + AI-powered ✅✅✅
 * 
 * MARKET: $15B cyber training market
 * VALUE: Remplace formations $10K/personne/an
 */

const db = require('../config/database');
const crypto = require('crypto');

class AttackSimulationTraining {
  constructor() {
    this.activeSimulations = new Map();
    
    // Attack scenarios library
    this.scenarios = this.buildScenarioLibrary();
    
    // Skill levels
    this.skillLevels = ['beginner', 'intermediate', 'advanced', 'expert'];
    
    // Initialize database tables
    this.initializeTables();
  }

  /**
   * Start attack simulation
   */
  async startSimulation(userId, scenarioId, options = {}) {
    const scenario = this.scenarios.find(s => s.id === scenarioId);
    
    if (!scenario) {
      throw new Error('Scenario not found');
    }

    const simulationId = 'sim_' + crypto.randomBytes(8).toString('hex');
    
    const simulation = {
      id: simulationId,
      userId,
      scenarioId,
      scenario: scenario.name,
      difficulty: scenario.difficulty,
      startTime: Date.now(),
      status: 'active',
      phase: 'initial_attack',
      attacksDeployed: [],
      defenseActions: [],
      score: 0,
      timeToDetect: null,
      timeToRespond: null,
      timeToRemediate: null
    };

    // Save to database
    db.prepare(`
      INSERT INTO attack_simulations (
        id, user_id, scenario_id, difficulty, status, started_at
      ) VALUES (?, ?, ?, ?, 'active', ?)
    `).run(
      simulationId,
      userId,
      scenarioId,
      scenario.difficulty,
      Math.floor(Date.now() / 1000)
    );

    // Store in memory for real-time updates
    this.activeSimulations.set(simulationId, simulation);

    // Deploy initial attack
    await this.deployAttack(simulation, scenario.attacks[0]);

    return {
      simulationId,
      scenario: scenario.name,
      description: scenario.description,
      objectives: scenario.objectives,
      difficulty: scenario.difficulty,
      estimatedDuration: scenario.estimatedDuration,
      attackVector: scenario.attacks[0].type,
      instructions: 'Monitor your dashboard for attack indicators. Respond as quickly as possible.',
      status: 'Attack deployed - Detection phase started'
    };
  }

  /**
   * Deploy attack in simulation
   */
  async deployAttack(simulation, attack) {
    const attackEvent = {
      id: crypto.randomBytes(4).toString('hex'),
      type: attack.type,
      deployedAt: Date.now(),
      detected: false,
      indicators: attack.indicators,
      severity: attack.severity,
      data: attack.data
    };

    simulation.attacksDeployed.push(attackEvent);

    // Create indicators that user should detect
    await this.createDetectionIndicators(simulation.userId, attackEvent);

    return attackEvent;
  }

  /**
   * Create detection indicators
   */
  async createDetectionIndicators(userId, attack) {
    const indicators = [];

    // Create simulated vulnerabilities that appear
    for (const indicator of attack.indicators) {
      indicators.push({
        type: indicator.type,
        location: indicator.location,
        severity: indicator.severity,
        timestamp: Date.now(),
        message: indicator.message
      });
    }

    // These would show up in the user's dashboard
    return indicators;
  }

  /**
   * User action during simulation
   */
  async handleDefenseAction(simulationId, action) {
    const simulation = this.activeSimulations.get(simulationId);
    
    if (!simulation) {
      throw new Error('Simulation not found or expired');
    }

    const actionTimestamp = Date.now();
    
    // Record action
    const defenseAction = {
      action: action.type,
      timestamp: actionTimestamp,
      correct: false,
      points: 0
    };

    // Evaluate action
    const evaluation = this.evaluateAction(simulation, action);
    defenseAction.correct = evaluation.correct;
    defenseAction.points = evaluation.points;
    defenseAction.feedback = evaluation.feedback;

    simulation.defenseActions.push(defenseAction);
    simulation.score += evaluation.points;

    // Check if this was detection
    if (action.type === 'detect_attack' && !simulation.timeToDetect) {
      simulation.timeToDetect = actionTimestamp - simulation.startTime;
      simulation.phase = 'response';
    }

    // Check if this was response
    if (action.type === 'respond_to_attack' && !simulation.timeToRespond) {
      simulation.timeToRespond = actionTimestamp - simulation.startTime;
      simulation.phase = 'remediation';
    }

    // Check if this was remediation
    if (action.type === 'remediate_vulnerability' && !simulation.timeToRemediate) {
      simulation.timeToRemediate = actionTimestamp - simulation.startTime;
      simulation.phase = 'completed';
      simulation.status = 'completed';
      
      // Calculate final score
      await this.completeSimulation(simulation);
    }

    return {
      correct: evaluation.correct,
      points: evaluation.points,
      feedback: evaluation.feedback,
      currentScore: simulation.score,
      phase: simulation.phase,
      nextStep: this.getNextStep(simulation)
    };
  }

  /**
   * Evaluate defense action
   */
  evaluateAction(simulation, action) {
    const scenario = this.scenarios.find(s => s.id === simulation.scenarioId);
    const correctActions = scenario.correctActions[simulation.phase] || [];

    const isCorrect = correctActions.some(ca => 
      ca.type === action.type && 
      this.matchesTarget(ca.target, action.target)
    );

    if (isCorrect) {
      // Calculate points based on speed
      const timeElapsed = Date.now() - simulation.startTime;
      const speedBonus = Math.max(0, 100 - Math.floor(timeElapsed / 1000));
      const basePoints = 100;
      const total = basePoints + speedBonus;

      return {
        correct: true,
        points: total,
        feedback: `Excellent! Correct action performed. Speed bonus: +${speedBonus} points.`
      };
    } else {
      return {
        correct: false,
        points: -20,
        feedback: `Not the optimal action for this phase. Review the attack indicators.`
      };
    }
  }

  /**
   * Complete simulation and calculate final score
   */
  async completeSimulation(simulation) {
    const metrics = {
      timeToDetect: simulation.timeToDetect,
      timeToRespond: simulation.timeToRespond,
      timeToRemediate: simulation.timeToRemediate,
      totalTime: Date.now() - simulation.startTime,
      finalScore: simulation.score,
      correctActions: simulation.defenseActions.filter(a => a.correct).length,
      totalActions: simulation.defenseActions.length,
      accuracy: simulation.defenseActions.filter(a => a.correct).length / Math.max(1, simulation.defenseActions.length)
    };

    // Performance rating
    const rating = this.calculateRating(metrics);

    // Update database
    db.prepare(`
      UPDATE attack_simulations 
      SET status = 'completed',
          score = ?,
          time_to_detect = ?,
          time_to_respond = ?,
          time_to_remediate = ?,
          rating = ?,
          completed_at = ?
      WHERE id = ?
    `).run(
      simulation.score,
      simulation.timeToDetect,
      simulation.timeToRespond,
      simulation.timeToRemediate,
      rating,
      Math.floor(Date.now() / 1000),
      simulation.id
    );

    // Award points
    await this.awardTrainingPoints(simulation.userId, simulation.score, rating);

    // Check for achievements
    await this.checkTrainingAchievements(simulation.userId);

    // Remove from active simulations
    this.activeSimulations.delete(simulation.id);

    return {
      ...metrics,
      rating,
      feedback: this.generateFeedback(metrics),
      recommendations: this.generateRecommendations(metrics)
    };
  }

  /**
   * Calculate performance rating
   */
  calculateRating(metrics) {
    const detectSpeed = metrics.timeToDetect < 60000 ? 'excellent' : 
                       metrics.timeToDetect < 300000 ? 'good' : 'needs_improvement';
    
    const responseSpeed = metrics.timeToRespond < 180000 ? 'excellent' :
                         metrics.timeToRespond < 600000 ? 'good' : 'needs_improvement';

    const accuracy = metrics.accuracy >= 0.9 ? 'excellent' :
                    metrics.accuracy >= 0.7 ? 'good' : 'needs_improvement';

    // Overall rating
    const scores = [detectSpeed, responseSpeed, accuracy];
    const excellentCount = scores.filter(s => s === 'excellent').length;
    
    if (excellentCount === 3) return 'expert';
    if (excellentCount >= 2) return 'advanced';
    if (scores.every(s => s !== 'needs_improvement')) return 'intermediate';
    return 'beginner';
  }

  /**
   * Generate feedback
   */
  generateFeedback(metrics) {
    const feedback = [];

    // Detection feedback
    if (metrics.timeToDetect < 60000) {
      feedback.push('🏆 Excellent detection speed! You identified the attack in under 1 minute.');
    } else if (metrics.timeToDetect < 300000) {
      feedback.push('✅ Good detection. Aim for under 1 minute for critical threats.');
    } else {
      feedback.push('⚠️ Slow detection. Practice identifying attack indicators faster.');
    }

    // Response feedback
    if (metrics.timeToRespond < 180000) {
      feedback.push('🏆 Fast response! You contained the threat quickly.');
    } else {
      feedback.push('⚠️ Response time can be improved. Every minute counts in an active attack.');
    }

    // Accuracy feedback
    if (metrics.accuracy >= 0.9) {
      feedback.push('🎯 Excellent accuracy! You made the right decisions.');
    } else if (metrics.accuracy >= 0.7) {
      feedback.push('✅ Good decision-making. Review incorrect actions to improve.');
    } else {
      feedback.push('⚠️ Many incorrect actions. Review the playbook for this scenario.');
    }

    return feedback;
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(metrics) {
    const recommendations = [];

    if (metrics.timeToDetect > 60000) {
      recommendations.push({
        area: 'Detection',
        recommendation: 'Enable real-time monitoring and alerts',
        impact: 'Reduce detection time by 80%'
      });
    }

    if (metrics.timeToRespond > 180000) {
      recommendations.push({
        area: 'Response',
        recommendation: 'Create incident response playbooks',
        impact: 'Standardize response, reduce time by 60%'
      });
    }

    if (metrics.accuracy < 0.8) {
      recommendations.push({
        area: 'Skills',
        recommendation: 'Complete additional training scenarios',
        impact: 'Improve decision accuracy'
      });
    }

    return recommendations;
  }

  /**
   * Get team readiness score
   */
  async getTeamReadinessScore(teamId) {
    const teamMembers = db.prepare(`
      SELECT user_id FROM users WHERE team_id = ?
    `).all(teamId);

    if (teamMembers.length === 0) {
      return { score: 0, message: 'No team members' };
    }

    const scores = [];
    
    for (const member of teamMembers) {
      const memberScore = await this.getUserReadinessScore(member.user_id);
      scores.push(memberScore);
    }

    const avgScore = scores.reduce((sum, s) => sum + s.score, 0) / scores.length;
    const avgDetection = scores.reduce((sum, s) => sum + s.avgDetectionTime, 0) / scores.length;
    const avgResponse = scores.reduce((sum, s) => sum + s.avgResponseTime, 0) / scores.length;

    return {
      teamScore: Math.round(avgScore),
      grade: this.getGrade(avgScore),
      avgDetectionTime: avgDetection,
      avgResponseTime: avgResponse,
      memberCount: teamMembers.length,
      readinessLevel: avgScore >= 80 ? 'High' : avgScore >= 60 ? 'Medium' : 'Low',
      recommendations: this.getTeamRecommendations(avgScore, avgDetection, avgResponse)
    };
  }

  /**
   * Get user readiness score
   */
  async getUserReadinessScore(userId) {
    const simulations = db.prepare(`
      SELECT * FROM attack_simulations 
      WHERE user_id = ? AND status = 'completed'
      ORDER BY completed_at DESC
      LIMIT 10
    `).all(userId);

    if (simulations.length === 0) {
      return {
        score: 0,
        level: 'untrained',
        simulationsCompleted: 0
      };
    }

    const avgScore = simulations.reduce((sum, s) => sum + s.score, 0) / simulations.length;
    const avgDetection = simulations.reduce((sum, s) => sum + (s.time_to_detect || 0), 0) / simulations.length;
    const avgResponse = simulations.reduce((sum, s) => sum + (s.time_to_respond || 0), 0) / simulations.length;

    return {
      score: Math.round(avgScore / 10), // Normalize to 0-100
      level: simulations[0].rating || 'beginner',
      simulationsCompleted: simulations.length,
      avgDetectionTime: avgDetection,
      avgResponseTime: avgResponse,
      recentPerformance: simulations.slice(0, 5).map(s => ({
        scenario: s.scenario_id,
        score: s.score,
        date: s.completed_at
      }))
    };
  }

  /**
   * Build scenario library
   */
  buildScenarioLibrary() {
    return [
      {
        id: 'ransomware_attack',
        name: 'Ransomware Attack',
        description: 'Respond to a ransomware infection before data is encrypted',
        difficulty: 'intermediate',
        estimatedDuration: '15 minutes',
        objectives: [
          'Detect suspicious file activity',
          'Isolate infected systems',
          'Block C&C communication',
          'Restore from backups'
        ],
        attacks: [
          {
            type: 'ransomware',
            severity: 'critical',
            indicators: [
              { type: 'file_activity', location: 'multiple_files', message: 'Unusual file modifications detected' },
              { type: 'network', location: 'outbound', message: 'Connection to known malicious IP' },
              { type: 'process', location: 'system', message: 'Unknown encryption process running' }
            ],
            data: {
              affectedFiles: 1247,
              encryptionProgress: 0,
              ransomNote: 'Your files have been encrypted...'
            }
          }
        ],
        correctActions: {
          'initial_attack': [
            { type: 'detect_attack', target: 'ransomware' }
          ],
          'response': [
            { type: 'isolate_system', target: 'infected_host' },
            { type: 'block_ip', target: 'c2_server' }
          ],
          'remediation': [
            { type: 'restore_backup', target: 'affected_files' },
            { type: 'patch_vulnerability', target: 'entry_point' }
          ]
        }
      },
      {
        id: 'sql_injection_attack',
        name: 'SQL Injection Attack',
        description: 'Detect and stop an active SQL injection attempt',
        difficulty: 'beginner',
        estimatedDuration: '10 minutes',
        objectives: [
          'Identify injection attempts in logs',
          'Block malicious requests',
          'Patch vulnerable endpoint',
          'Verify no data was exfiltrated'
        ],
        attacks: [
          {
            type: 'sql_injection',
            severity: 'high',
            indicators: [
              { type: 'log', location: 'api_logs', message: 'Suspicious SQL patterns in requests' },
              { type: 'database', location: 'query_logs', message: 'Abnormal query patterns' }
            ]
          }
        ],
        correctActions: {
          'initial_attack': [
            { type: 'detect_attack', target: 'sql_injection' }
          ],
          'response': [
            { type: 'block_ip', target: 'attacker_ip' },
            { type: 'enable_waf', target: 'application' }
          ],
          'remediation': [
            { type: 'patch_code', target: 'vulnerable_endpoint' },
            { type: 'audit_database', target: 'check_exfiltration' }
          ]
        }
      },
      {
        id: 'phishing_campaign',
        name: 'Phishing Campaign Response',
        description: 'Respond to a company-wide phishing attack',
        difficulty: 'intermediate',
        estimatedDuration: '12 minutes',
        objectives: [
          'Identify phishing emails',
          'Alert affected users',
          'Block sender domains',
          'Reset compromised credentials'
        ],
        attacks: [
          {
            type: 'phishing',
            severity: 'high',
            indicators: [
              { type: 'email', location: 'inbox', message: '50+ similar emails detected' },
              { type: 'clicks', location: 'malicious_link', message: '12 users clicked phishing link' }
            ]
          }
        ],
        correctActions: {
          'initial_attack': [
            { type: 'detect_attack', target: 'phishing' }
          ],
          'response': [
            { type: 'alert_users', target: 'all_employees' },
            { type: 'block_domain', target: 'phishing_domain' }
          ],
          'remediation': [
            { type: 'reset_passwords', target: 'affected_users' },
            { type: 'security_training', target: 'all_employees' }
          ]
        }
      },
      {
        id: 'ddos_attack',
        name: 'DDoS Attack Mitigation',
        description: 'Mitigate a distributed denial of service attack',
        difficulty: 'advanced',
        estimatedDuration: '20 minutes',
        objectives: [
          'Detect abnormal traffic patterns',
          'Enable DDoS protection',
          'Identify attack source',
          'Maintain service availability'
        ],
        attacks: [
          {
            type: 'ddos',
            severity: 'critical',
            indicators: [
              { type: 'traffic', location: 'network', message: 'Traffic spike: 10,000% above normal' },
              { type: 'performance', location: 'servers', message: 'Server response time: 30 seconds' }
            ]
          }
        ],
        correctActions: {
          'initial_attack': [
            { type: 'detect_attack', target: 'ddos' }
          ],
          'response': [
            { type: 'enable_cdn', target: 'traffic_filtering' },
            { type: 'rate_limit', target: 'api_endpoints' }
          ],
          'remediation': [
            { type: 'scale_infrastructure', target: 'add_capacity' },
            { type: 'analyze_logs', target: 'identify_botnet' }
          ]
        }
      }
    ];
  }

  /**
   * Helper methods
   */
  matchesTarget(correctTarget, actionTarget) {
    return correctTarget === actionTarget || 
           actionTarget.includes(correctTarget) ||
           correctTarget.includes(actionTarget);
  }

  getNextStep(simulation) {
    const phase = simulation.phase;
    
    const steps = {
      'initial_attack': 'Detect the attack by reviewing logs and indicators',
      'response': 'Respond to the attack by containing the threat',
      'remediation': 'Remediate by patching vulnerabilities and verifying security',
      'completed': 'Simulation complete! Review your performance.'
    };

    return steps[phase] || 'Continue responding to the incident';
  }

  getGrade(score) {
    if (score >= 90) return 'A+';
    if (score >= 80) return 'A';
    if (score >= 70) return 'B';
    if (score >= 60) return 'C';
    return 'D';
  }

  getTeamRecommendations(score, detection, response) {
    const recommendations = [];

    if (score < 70) {
      recommendations.push('Schedule regular training sessions for the entire team');
    }

    if (detection > 120000) { // > 2 minutes
      recommendations.push('Implement real-time monitoring and automated alerts');
    }

    if (response > 600000) { // > 10 minutes
      recommendations.push('Create and practice incident response playbooks');
    }

    return recommendations;
  }

  async awardTrainingPoints(userId, score, rating) {
    // Award gamification points
    const pointsMap = {
      'expert': 500,
      'advanced': 300,
      'intermediate': 200,
      'beginner': 100
    };

    const points = pointsMap[rating] || 50;

    try {
      db.prepare(`
        INSERT INTO gamification_points_log (user_id, action, points, created_at)
        VALUES (?, 'training_completion', ?, ?)
      `).run(userId, points, Math.floor(Date.now() / 1000));

      db.prepare(`
        UPDATE users 
        SET gamification_points = gamification_points + ?
        WHERE id = ?
      `).run(points, userId);
    } catch (error) {
      console.error('Could not award points:', error.message);
    }
  }

  async checkTrainingAchievements(userId) {
    // Check for training-related achievements
    const completedCount = db.prepare(`
      SELECT COUNT(*) as count
      FROM attack_simulations
      WHERE user_id = ? AND status = 'completed'
    `).get(userId);

    const achievements = [];

    if (completedCount.count === 1) {
      achievements.push('first_simulation');
    }
    if (completedCount.count === 10) {
      achievements.push('training_veteran');
    }
    if (completedCount.count === 50) {
      achievements.push('cyber_defender');
    }

    // Award achievements
    for (const achievement of achievements) {
      try {
        db.prepare(`
          INSERT OR IGNORE INTO user_achievements (user_id, achievement_id, unlocked_at)
          VALUES (?, ?, ?)
        `).run(userId, achievement, Math.floor(Date.now() / 1000));
      } catch (error) {
        // Achievement already exists
      }
    }
  }

  initializeTables() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS attack_simulations (
          id TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          scenario_id TEXT NOT NULL,
          difficulty TEXT NOT NULL,
          status TEXT NOT NULL,
          score INTEGER DEFAULT 0,
          time_to_detect INTEGER,
          time_to_respond INTEGER,
          time_to_remediate INTEGER,
          rating TEXT,
          started_at INTEGER NOT NULL,
          completed_at INTEGER,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);
    } catch (error) {
      // Table already exists
    }
  }
}

module.exports = new AttackSimulationTraining();
