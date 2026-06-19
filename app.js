/* =========================================================
   Cloudflare Security Lab
   app.js (Fully Unified & Synchronized Edition)
========================================================= */

const API_URL = "https://cloudflarelab-api.wincapz20.workers.dev/";

const state = {
  totalRequests: 0,
  visitors: 0,
  botScore: 100,
  cacheHitRatio: 0,
  wafEvents: 0,
  rateLimited: 0,
  threatEvents: 0,
  ja3: 0,
  ja4: 0,
  cacheHits: 0,
  cacheMisses: 0,
  rps: 0,

  countries: {
    US: 0,
    DE: 0,
    JP: 0,
    SG: 0,
    PH: 0,
    BR: 0
  }
};

/* =========================================================
   DOM REFERENCES
========================================================= */

const totalRequestsEl = document.getElementById("totalRequests");
const rpsEl = document.getElementById("rps");
const visitorsEl = document.getElementById("visitors");
const botScoreEl = document.getElementById("botScore");
const cacheHitRatioEl = document.getElementById("cacheHitRatio");
const wafEventsEl = document.getElementById("wafEvents");
const rateLimitedEl = document.getElementById("rateLimited");
const threatEventsEl = document.getElementById("threatEvents");
const ja3CountEl = document.getElementById("ja3Count");
const ja4CountEl = document.getElementById("ja4Count");

const tlsJa3El = document.getElementById("tlsJa3");
const tlsJa4El = document.getElementById("tlsJa4");

const cacheHitsEl = document.getElementById("cacheHits");
const cacheMissesEl = document.getElementById("cacheMisses");
const cacheRatioEl = document.getElementById("cacheRatio");

const liveCounterEl = document.getElementById("liveCounter");
const activityLogEl = document.getElementById("activityLog");

const countryUS = document.getElementById("countryUS");
const countryDE = document.getElementById("countryDE");
const countryJP = document.getElementById("countryJP");
const countrySG = document.getElementById("countrySG");
const countryPH = document.getElementById("countryPH");
const countryBR = document.getElementById("countryBR");

const trafficAmountInput = document.getElementById("trafficAmount");
const systemStatus = document.getElementById("systemStatus");

/* =========================================================
   CHARTS INITIALIZATION
========================================================= */

const trafficChart = new Chart(
  document.getElementById("trafficChart"),
  {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Requests",
        data: [],
        borderColor: "#f48120",
        backgroundColor: "rgba(244, 129, 32, 0.15)",
        borderWidth: 3,
        tension: 0.3,
        fill: true
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false
    }
  }
);

const securityChart = new Chart(
  document.getElementById("securityChart"),
  {
    type: "bar",
    data: {
      labels: [],
      datasets: [{
        label: "Threat Events",
        data: [],
        backgroundColor: "#ef4444"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            stepSize: 1
          }
        }
      }
    }
  }
);

/* =========================================================
   HELPERS
========================================================= */

/* =========================================================
   HELPERS (Fixed Input Field Range Check)
========================================================= */

function getTrafficAmount() {
  const inputEl = document.getElementById("trafficAmount");
  
  // If the input element is missing on the HTML, default to 50
  if (!inputEl) return 1;

  let value = parseInt(inputEl.value);

  // If the box is empty or not a valid number, default to 50
  if (isNaN(value)) {
    return 1;
  }

  // Enforce a safe range between 1 and 100 so your browser doesn't freeze
  if (value < 1) return 1;
  if (value > 100) return 100;

  return value;
}

function timeLabel() {
  return new Date().toLocaleTimeString();
}

function randomCountry() {
  const countries = ["US", "DE", "JP", "SG", "PH", "BR"];
  return countries[Math.floor(Math.random() * countries.length)];
}

function addLog(message, type = "success") {
  const div = document.createElement("div");
  div.className = `log-entry log-${type}`;
  div.innerHTML = `[${timeLabel()}] ${message}`;
  activityLogEl.prepend(div);

  while (activityLogEl.children.length > 100) {
    activityLogEl.removeChild(activityLogEl.lastChild);
  }
}

/* =========================================================
   METRICS UPDATE
========================================================= */

function updateMetrics() {
  totalRequestsEl.textContent = state.totalRequests.toLocaleString();
  visitorsEl.textContent = state.visitors.toLocaleString();
  botScoreEl.textContent = `${state.botScore}%`;
  cacheHitRatioEl.textContent = `${state.cacheHitRatio}%`;
  wafEventsEl.textContent = state.wafEvents.toLocaleString();
  rateLimitedEl.textContent = state.rateLimited.toLocaleString();
  threatEventsEl.textContent = state.threatEvents.toLocaleString();
  ja3CountEl.textContent = state.ja3.toLocaleString();
  ja4CountEl.textContent = state.ja4.toLocaleString();
  tlsJa3El.textContent = state.ja3.toLocaleString();
  tlsJa4El.textContent = state.ja4.toLocaleString();
  cacheHitsEl.textContent = state.cacheHits.toLocaleString();
  cacheMissesEl.textContent = state.cacheMisses.toLocaleString();
  cacheRatioEl.textContent = `${state.cacheHitRatio}%`;
  liveCounterEl.textContent = state.totalRequests.toLocaleString();
  rpsEl.textContent = state.rps.toLocaleString();

  countryUS.textContent = state.countries.US;
  countryDE.textContent = state.countries.DE;
  countryJP.textContent = state.countries.JP;
  countrySG.textContent = state.countries.SG;
  countryPH.textContent = state.countries.PH;
  countryBR.textContent = state.countries.BR;
}

/* =========================================================
   WORKER API CALL (With Force-Logging Cache Buster)
========================================================= */

async function callAPI(payload) {
  try {
    // Generates a totally unique string for every single network packet
    const cacheBuster = `cb=${Date.now()}_${Math.floor(Math.random() * 1000000)}`;
    
    // Attaches the unique string to the URL (e.g., https://...workers.dev/?cb=1718821920_48291)
    const uniqueURL = API_URL.includes('?') ? `${API_URL}&${cacheBuster}` : `${API_URL}?${cacheBuster}`;

    const response = await fetch(uniqueURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    return await response.json();
  } catch (error) {
    console.error("API Error:", error);
    return null;
  }
}


/* =========================================================
   PROCESS INCOMING DATA PACKETS (With Current Time Grouping)
========================================================= */

function applyResponse(data) {
  if (!data) return;

  state.totalRequests += data.count || 0;
  state.visitors += data.visitors || 0;
  
  if (data.botScore !== undefined) state.botScore = data.botScore;

  state.wafEvents += data.wafEvents || 0;
  state.rateLimited += data.rateLimited || 0;
  state.threatEvents += data.threatEvents || 0;
  state.ja3 += data.ja3 || 0;
  state.ja4 += data.ja4 || 0;
  state.cacheHits += data.cacheHits || 0;
  state.cacheMisses += data.cacheMisses || 0;
  state.rps = data.requestsPerSecond || data.count || 0;

  const totalCache = state.cacheHits + state.cacheMisses;
  if (totalCache > 0) {
    state.cacheHitRatio = Math.round((state.cacheHits / totalCache) * 100);
  }

  const countryCode = data.country || randomCountry();
  if (state.countries[countryCode] !== undefined) {
    state.countries[countryCode] += data.count || 1;
  }

  updateMetrics();

  /* =========================================================
     FIXED CHART ENGINE: Uses currentTime to group bars
     ========================================================= */
  const currentTime = timeLabel(); // <-- This creates the timestamp variable

  // 1. Group Traffic Data
  const trafficTimeIndex = trafficChart.data.labels.indexOf(currentTime);
  if (trafficTimeIndex !== -1) {
    trafficChart.data.datasets[0].data[trafficTimeIndex] += data.count || 0;
  } else {
    trafficChart.data.labels.push(currentTime);
    trafficChart.data.datasets[0].data.push(data.count || 0);
  }

  if (trafficChart.data.labels.length > 15) {
    trafficChart.data.labels.shift();
    trafficChart.data.datasets[0].data.shift();
  }
  trafficChart.update();

  // 2. Group Security Threat Data
  const securityTimeIndex = securityChart.data.labels.indexOf(currentTime);
  if (securityTimeIndex !== -1) {
    securityChart.data.datasets[0].data[securityTimeIndex] += data.threatEvents || 0;
  } else {
    securityChart.data.labels.push(currentTime);
    securityChart.data.datasets[0].data.push(data.threatEvents || 0);
  }

  if (securityChart.data.labels.length > 15) {
    securityChart.data.labels.shift();
    securityChart.data.datasets[0].data.shift();
  }
  securityChart.update();
}

/* =========================================================
   TRAFFIC GENERATION ACTIONS
========================================================= */

async function generateTraffic(type) {
  const amount = getTrafficAmount();
  addLog(`Generating ${amount} requests using profile: ${type.toUpperCase()}`, "info");

  for (let i = 0; i < amount; i++) {
    callAPI({ action: "traffic", profile: type, count: 1 }).then(result => {
      if (result) applyResponse(result);
    });
    await new Promise(resolve => setTimeout(resolve, 15));
  }
}

async function simulateAttack(type) {
  const amount = getTrafficAmount();
  addLog(`🔥 Triggering real WAF attack load: ${amount} ${type.toUpperCase()} exploits...`, "danger");

  for (let i = 0; i < amount; i++) {
    callAPI({ action: "attack", attackType: type, count: 1 }).then(result => {
      if (result) applyResponse(result);
    });
    await new Promise(resolve => setTimeout(resolve, 15));
  }
}

/* =========================================================
   EDGE STATUS SIMULATOR (Fixed to bypass Local Disk Cache)
========================================================= */

async function simulateStatus(code) {
  const amount = getTrafficAmount();
  addLog(`Simulating ${amount} requests returning status ${code}...`, "info");

  for (let i = 0; i < amount; i++) {
    // Cache Buster: Appends a completely unique number to every single loop iteration
    const uniqueBuster = `cb=${Date.now()}_${Math.floor(Math.random() * 1000000)}`;
    const targetURL = `${API_URL}status/${code}?${uniqueBuster}`;

    fetch(targetURL)
      .then(response => {
        const payload = {
          count: 1,
          requestsPerSecond: 1,
          threatEvents: (code >= 400) ? 1 : 0 
        };
        applyResponse(payload);
      })
      .catch(err => console.error(err));
      
    await new Promise(resolve => setTimeout(resolve, 15));
  }
  addLog(`Completed generating status ${code} events.`, "success");
}

async function securityTest(type) {
  const result = await callAPI({ action: "security", test: type });
  applyResponse(result);
  addLog(`Executed platform security execution check: ${type.toUpperCase()}`);
}

/* =========================================================
   EVENT LISTENERS
========================================================= */

document.getElementById("normalTrafficBtn").addEventListener("click", () => generateTraffic("normal"));
document.getElementById("trafficSpikeBtn").addEventListener("click", () => generateTraffic("spike"));
document.getElementById("botTrafficBtn").addEventListener("click", () => generateTraffic("bot"));

document.querySelectorAll("[data-profile]").forEach(btn => {
  btn.addEventListener("click", () => generateTraffic(btn.dataset.profile));
});

document.querySelectorAll("[data-attack]").forEach(btn => {
  btn.addEventListener("click", () => simulateAttack(btn.dataset.attack));
});

document.querySelectorAll("[data-status]").forEach(btn => {
  btn.addEventListener("click", () => simulateStatus(btn.dataset.status));
});

document.getElementById("wafTestBtn").addEventListener("click", () => securityTest("waf"));
document.getElementById("rateLimitBtn").addEventListener("click", () => securityTest("rate_limit"));
document.getElementById("loginAttackBtn").addEventListener("click", () => securityTest("login"));
document.getElementById("cacheTestBtn").addEventListener("click", () => securityTest("cache"));
document.getElementById("errorTestBtn").addEventListener("click", () => securityTest("404"));

document.getElementById("allowBotsBtn").addEventListener("click", () => securityTest("allow_bots"));
document.getElementById("challengeBotsBtn").addEventListener("click", () => securityTest("challenge_bots"));
document.getElementById("blockBotsBtn").addEventListener("click", () => securityTest("block_bots"));
document.getElementById("verifiedBotBtn").addEventListener("click", () => securityTest("verified_bot"));


/* =========================================================
   HYBRID BACKGROUND BLASTER (Real Traffic + 1-100 Visual Scale)
========================================================= */

setInterval(async () => {
  // 1. Generate a beautiful, fluctuating baseline value strictly between 1 and 100
  const simulatedPulse = Math.floor(Math.random() * 100) + 1; 

  // 2. Determine a safe number of actual physical packets to send based on that pulse
  // We use Math.min to ensure your browser never tries to fire more than 10 physical requests at once
  const actualPackets = Math.min(Math.ceil(simulatedPulse * 0.1), 10);
  
  addLog(`Automated background sync: Synchronizing analytics with Cloudflare Edge...`, "info");

  // 3. Fire the actual network packets so your real Cloudflare dashboard increments
  for (let i = 0; i < actualPackets; i++) {
    const profiles = ["normal", "spike", "bot"];
    const randomProfile = profiles[Math.floor(Math.random() * profiles.length)];

    callAPI({ 
      action: "traffic", 
      profile: randomProfile, 
      count: 1 
    }); // Fires background packets directly into Cloudflare's servers
    
    await new Promise(resolve => setTimeout(resolve, 25));
  }

  // 4. Update your frontend metrics and charts using the 1-100 scaled value
  state.totalRequests += simulatedPulse;
  state.visitors += Math.floor(simulatedPulse * 0.15) + 1; // Visitors scale naturally
  state.rps = simulatedPulse;
  
  updateMetrics();
  
  const currentTickTime = timeLabel();

  // 5. Update the Live Traffic Line Chart with the 1-100 number
  if (!trafficChart.data.labels.includes(currentTickTime)) {
    trafficChart.data.labels.push(currentTickTime);
    trafficChart.data.datasets[0].data.push(simulatedPulse); // Injects the clean 1-100 values

    if (trafficChart.data.labels.length > 15) {
      trafficChart.data.labels.shift();
      trafficChart.data.datasets[0].data.shift();
    }
    trafficChart.update();

    // Keep Security Bar Chart steady at 0 baseline
    securityChart.data.labels.push(currentTickTime);
    securityChart.data.datasets[0].data.push(0); 
    if (securityChart.data.labels.length > 15) {
      securityChart.data.labels.shift();
      securityChart.data.datasets[0].data.shift();
    }
    securityChart.update();
  }

}, 4000); // Runs a fresh wave every 4 seconds

/* =========================================================
   INITIALIZATION
========================================================= */
addLog("Cloudflare Security Lab initialized");
updateMetrics();
