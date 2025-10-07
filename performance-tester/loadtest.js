import http from 'k6/http';
import { sleep, check } from 'k6';

// simulating 10,000 visits per hr
// Calculate how many VUs you need based on your request rate
const REQUEST_INTERVAL_SECONDS = 0.18; // Adjust based on your needs
const VUS = Math.ceil(27.77 * REQUEST_INTERVAL_SECONDS); // Number of VUs
const TEST_URL = "https://google.com"; // sample URL

export let options = {
    stages: [
        { duration: '30m', target: VUS }, // Simulate this load for 1 hour
    ],
    thresholds: {
        http_req_duration: ['p(95)<2000'], // Ensure performance thresholds are met
    },
};

export default function () {
    let response = http.get(TEST_URL); 
    check(response, { 'status is 200': (r) => r.status === 200 });
    
    sleep(REQUEST_INTERVAL_SECONDS); // Control the rate of requests
}
