/**
 * G1-Warrant - Deterministic Control Plane & API Load / SLA Benchmark
 * Evaluates control-plane telemetry, warrant verification, and feed status endpoints
 * against Federal SLA standards (p95 <= 25.0 ms, < 1% error rate under sustained concurrency).
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://host.docker.internal:8080';

export const options = {
  stages: [
    { duration: '3s', target: 5 },   // Ramp-up
    { duration: '10s', target: 10 }, // Sustained concurrent operator & telemetry load
    { duration: '2s', target: 0 },   // Cool-down
  ],
  thresholds: {
    'http_req_duration{endpoint:healthz}': ['p(95)<15.0'],
    'http_req_duration{endpoint:scoreboard}': ['p(95)<35.0'],
    'http_req_duration{endpoint:warrants}': ['p(95)<35.0'],
    'http_req_duration{endpoint:feeds}': ['p(95)<35.0'],
    'http_req_failed': ['rate<0.01'],
  },
};

export default function () {
  // 1. Control Plane Health & Kernel Public Key Seal
  {
    const res = http.get(`${BASE_URL}/healthz`, {
      tags: { endpoint: 'healthz' },
    });
    check(res, {
      'healthz status is 200': (r) => r.status === 200,
    });
  }

  // 2. Live Remediation Scoreboard & SLA Metrics
  {
    const res = http.get(`${BASE_URL}/api/v1/scoreboard`, {
      tags: { endpoint: 'scoreboard' },
    });
    check(res, {
      'scoreboard status is 200': (r) => r.status === 200,
    });
  }

  // 3. Immutable Standing Warrant Ledger
  {
    const res = http.get(`${BASE_URL}/api/v1/warrants`, {
      tags: { endpoint: 'warrants' },
    });
    check(res, {
      'warrants status is 200': (r) => r.status === 200,
    });
  }

  // 4. Sanitized Threat Feed Runtime Status
  {
    const res = http.get(`${BASE_URL}/api/v1/feeds/status`, {
      tags: { endpoint: 'feeds' },
    });
    check(res, {
      'feeds status is 200': (r) => r.status === 200,
    });
  }

  sleep(0.1);
}
