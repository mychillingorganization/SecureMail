const API_BASE = localStorage.getItem('securemail_api_base') || 'http://127.0.0.1:8080';

const emailPathEl = document.getElementById('emailPath');
const verdictEl = document.getElementById('verdict');
const summaryEl = document.getElementById('summary');
const logsEl = document.getElementById('logs');
const rawEl = document.getElementById('raw');
const dangerReasonsEl = document.getElementById('dangerReasons');
const safeReasonsEl = document.getElementById('safeReasons');

function renderList(root, items) {
  root.innerHTML = '';
  if (!items.length) {
    const li = document.createElement('li');
    li.textContent = 'None';
    root.appendChild(li);
    return;
  }
  for (const item of items) {
    const li = document.createElement('li');
    li.textContent = item;
    root.appendChild(li);
  }
}

function parseReasons(logs) {
  const danger = [];
  const safe = [];
  for (const line of logs) {
    if (line.includes('Danger reasons -')) {
      danger.push(...line.split('Danger reasons -')[1].split(',').map((x) => x.trim()).filter(Boolean));
    }
    if (line.includes('Safe reasons -')) {
      safe.push(...line.split('Safe reasons -')[1].split(',').map((x) => x.trim()).filter(Boolean));
    }
  }
  return { danger, safe };
}

async function run(endpoint) {
  const payload = {
    email_path: emailPathEl.value.trim(),
    user_accepts_danger: false,
  };

  const response = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json();

  verdictEl.textContent = `${data.final_status} (issues=${data.issue_count})`;
  verdictEl.className = `verdict ${String(data.final_status || '').toLowerCase()}`;
  summaryEl.textContent = data.termination_reason || 'No termination reason';

  const logs = Array.isArray(data.execution_logs) ? data.execution_logs : [];
  logsEl.textContent = logs.join('\n');
  rawEl.textContent = JSON.stringify(data, null, 2);

  const reasons = parseReasons(logs);
  renderList(dangerReasonsEl, reasons.danger);
  renderList(safeReasonsEl, reasons.safe);
}

document.getElementById('scanBtn').addEventListener('click', () => run('/api/v1/scan'));
document.getElementById('scanLlmBtn').addEventListener('click', () => run('/api/v1/scan-llm'));
