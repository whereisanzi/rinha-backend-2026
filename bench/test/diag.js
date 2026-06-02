// Diagnostic-only k6 script (NOT the official scorer). Same load profile as
// test.js but dumps the full http_req_* phase breakdown so we can localize
// where end-to-end latency is spent (waiting = server, blocked/connecting =
// connection setup, sending/receiving = transfer).
import http from 'k6/http';
import { SharedArray } from 'k6/data';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.1/index.js';
import exec from 'k6/execution';

const testData = new SharedArray('test-data', function () {
    return JSON.parse(open('./test-data.json')).entries;
});

export const options = {
    summaryTrendStats: ['min', 'avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'p(99.9)', 'max'],
    scenarios: {
        default: {
            executor: 'ramping-arrival-rate',
            startRate: 1,
            timeUnit: '1s',
            preAllocatedVUs: 100,
            maxVUs: 250,
            gracefulStop: '10s',
            stages: [{ duration: '120s', target: 900 }],
        },
    },
};

const TARGET = __ENV.TARGET || 'http://localhost:9999/fraud-score';

export default function () {
    const idx = exec.scenario.iterationInTest;
    if (idx >= testData.length) return;
    http.post(
        TARGET,
        JSON.stringify(testData[idx].request),
        { headers: { 'Content-Type': 'application/json' }, timeout: '2001ms' }
    );
}

export function handleSummary(data) {
    return { stdout: textSummary(data, { indent: ' ', enableColors: false }) };
}
