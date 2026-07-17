import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import https from 'https';

const TARGET_URLS = [
  "https://scan-bice.vercel.app"
];

const SCAN_INTERVAL_MS = 15000; // 15 seconds
const API_URL = "http://localhost:3000/api/scan";

const baselines = new Map();

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const options = {
      hostname: parsedUrl.hostname,
      path: parsedUrl.pathname + parsedUrl.search,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache"
      }
    };

    https.get(url, options, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} - ID: ${res.headers['x-vercel-id'] || 'N/A'}`));
        return;
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

async function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function establishBaselines() {
  console.log(chalk.cyanBright("==========================================="));
  console.log(chalk.cyanBright("   DATUM SYSTEM SIEGE MONITOR DAEMON       "));
  console.log(chalk.cyanBright("==========================================="));
  console.log(chalk.gray(`[${new Date().toISOString()}] Initializing engine...`));

  for (const url of TARGET_URLS) {
    console.log(chalk.yellow(`[*] Establishing baseline for ${url}...`));
    try {
      const html = await httpsGet(url);
      baselines.set(url, html);
      console.log(chalk.green(`[+] Baseline established: ${html.length} bytes captured.`));
    } catch (err) {
      console.log(chalk.red(`[-] Failed to baseline ${url}: ${err.message}`));
    }
  }
}

async function runScan(url) {
  const baselineHtml = baselines.get(url);
  if (!baselineHtml) {
    console.log(chalk.gray(`Skipping ${url} (no baseline)`));
    return;
  }

  process.stdout.write(chalk.blue(`[~] Scanning ${url}... `));

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: url, baselineHtml, withAi: true }),
    });

    if (!res.ok) {
      const err = await res.text();
      console.log(chalk.red(`ERROR HTTP ${res.status}`));
      return;
    }

    const data = await res.json();
    if (!data.ok) {
      console.log(chalk.red(`SCAN FAILED: ${data.error}`));
      return;
    }

    const { scan, verdict } = data;
    
    // Clear line
    process.stdout.write("\r\x1b[K");

    console.log(chalk.cyanBright(`\n--- Scan Result [${new Date().toLocaleTimeString()}] ---`));
    console.log(chalk.gray(`Target: `) + chalk.white(url));

    if (scan.posture === "secure") {
      console.log(chalk.green(`[✓] POSTURE: SECURE | SCORE: ${scan.postureScore}/100 | DRIFT: ${scan.driftPct}%`));
    } else if (scan.posture === "watch") {
      console.log(chalk.yellow(`[!] POSTURE: WATCH | SCORE: ${scan.postureScore}/100 | DRIFT: ${scan.driftPct}%`));
    } else {
      console.log(chalk.red.bold(`[X] POSTURE: CRITICAL | SCORE: ${scan.postureScore}/100 | DRIFT: ${scan.driftPct}%`));
    }

    if (verdict) {
      console.log(chalk.magenta(`🤖 AI Verdict: `) + chalk.bold(verdict.verdict) + chalk.gray(` (Confidence: ${Math.round(verdict.confidence * 100)}%)`));
      console.log(chalk.italic.dim(`   "${verdict.summary}"`));
    } else {
      console.log(chalk.gray(`🤖 AI Verdict: Offline`));
    }

    // If AI detects a major issue, trigger the forensic report!
    if (scan.posture === "critical" && verdict && (verdict.verdict === "DEFACEMENT" || verdict.verdict === "AT RISK")) {
      await generateForensicReport(url, scan, verdict);
    }

  } catch (err) {
    process.stdout.write("\r\x1b[K");
    console.log(chalk.red(`[-] Network error hitting API: ${err.message}`));
  }
}

async function generateForensicReport(url, scan, verdict) {
  console.log(chalk.bgRed.white.bold("\n >>> THREAT DETECTED! INITIATING FORENSIC REPORT <<< \n"));
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `INCIDENT-REPORT-${timestamp}.md`;
  
  const report = `
# 🚨 DATUM INCIDENT FORENSIC REPORT 🚨
**Date**: ${new Date().toISOString()}
**Target**: ${url}
**Severity**: CRITICAL (Score: ${scan.postureScore}/100)

---

## 🤖 AI Threat Intelligence Analysis
**Verdict**: ${verdict.verdict} (Confidence: ${Math.round(verdict.confidence * 100)}%)
**Executive Summary**: ${verdict.summary}
${verdict.error ? `**AI Error**: ${verdict.error}` : ''}

### 👤 Threat Actor Profile
> ${verdict.threatActorProfile || "Profile unavailable"}

### ⚔️ Likely Attack Vector
> ${verdict.likelyAttackVector || "Vector analysis unavailable"}

### 📊 Probabilistic Attack Path (Mermaid)
\`\`\`mermaid
${verdict.mermaidGraph || "graph TD\\n  Unknown-->Defacement"}
\`\`\`

---

## 🔍 Technical Scan Findings
- **Drift Detected**: ${scan.driftPct}% (Changed Tokens: ${scan.contentChanged})
- **Stack Fingerprint**: ${scan.fingerprint || "Unknown"}
- **HTTP Status**: ${scan.httpStatus}

### Detected Vulnerabilities
${scan.findings.map(f => `- **[${f.risk.toUpperCase()}]** (${f.category}) ${f.title}: ${f.detail}\n  *Remediation: ${f.remediation}*`).join('\n')}

---
*Report generated automatically by Datum Monitor Daemon.*
`;

  fs.writeFileSync(path.join(__dirname, filename), report.trim());
  console.log(chalk.red(`[!] Forensic report saved to ${filename}`));
  
  // Pause scanning for this target to avoid spamming reports
  baselines.delete(url);
  console.log(chalk.gray(`[i] Target isolated. Pausing future scans for ${url} until re-baselined.`));
}

async function main() {
  await establishBaselines();
  
  console.log(chalk.gray(`\nStarting polling loop (every ${SCAN_INTERVAL_MS/1000}s)... Press Ctrl+C to exit.\n`));
  
  setInterval(async () => {
    for (const url of TARGET_URLS) {
      await runScan(url);
    }
  }, SCAN_INTERVAL_MS);
}

main();
