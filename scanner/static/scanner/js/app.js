/**
 * NetScan Pro — Frontend Logic
 */

let currentJobId = null;
let pollInterval = null;
let isCancelled = false;

// ─── Port Range ───────────────────────────────────
function setPreset(el, value) {
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');

  const customBox = document.getElementById('customPortBox');
  const hidden    = document.getElementById('portRangeValue');

  if (value === 'custom') {
    customBox.style.display = 'block';
    hidden.value = document.getElementById('portInput').value || '1-1024';
  } else {
    customBox.style.display = 'none';
    hidden.value = value;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const portInput = document.getElementById('portInput');
  if (portInput) {
    portInput.addEventListener('input', () => {
      document.getElementById('portRangeValue').value = portInput.value;
    });
  }

  const targetInput = document.getElementById('targetInput');
  if (targetInput) {
    targetInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') startScan();
    });
  }
});

// ─── Resolve target (quick validation) ───────────
async function resolveTarget() {
  const target = document.getElementById('targetInput').value.trim();
  const hint   = document.getElementById('resolveHint');
  if (!target) return;
  hint.style.color = 'var(--cyan)';
  hint.textContent = 'Validating...';
  setTimeout(() => {
    hint.textContent = target.match(/^[\d.]+$/) || target.includes('.')
      ? `✓ Target looks valid: ${target}`
      : '⚠ Enter a valid IP or domain';
    hint.style.color = hint.textContent.startsWith('✓') ? 'var(--green)' : 'var(--yellow)';
  }, 400);
}

// ─── Start Scan ───────────────────────────────────
async function startScan() {
  const target    = (document.getElementById('targetInput')?.value || '').trim();
  const portRange = document.getElementById('portRangeValue')?.value || '1-1024';
  const scanType  = document.querySelector('input[name="scanType"]:checked')?.value || 'tcp';
  const hint      = document.getElementById('resolveHint');

  if (!target) {
    if (hint) { hint.textContent = '⚠ Please enter a target IP or domain.'; hint.style.color = 'var(--red)'; }
    document.getElementById('targetInput')?.focus();
    return;
  }

  isCancelled   = false;
  currentJobId  = null;
  setFormDisabled(true);
  showProgress();
  hideResults();
  updateProgress(5, 'Connecting to scanner...');

  try {
    const res  = await fetch('/scan/start/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
      body: JSON.stringify({ target, port_range: portRange, scan_type: scanType }),
    });
    const data = await res.json();

    if (!res.ok || data.error) {
      showError(data.error || 'Failed to start scan.');
      return;
    }

    currentJobId = data.job_id;
    pollStatus();
  } catch (err) {
    showError('Network error: ' + err.message);
  }
}

// ─── Poll ─────────────────────────────────────────
function pollStatus() {
  if (pollInterval) clearInterval(pollInterval);
  let tick = 0;

  pollInterval = setInterval(async () => {
    if (isCancelled || !currentJobId) { clearInterval(pollInterval); return; }
    tick++;

    try {
      const res  = await fetch(`/scan/${currentJobId}/status/`);
      const data = await res.json();
      const pct  = Math.min(92, 8 + tick * 9);

      updateProgress(pct, `Scanning ${data.target} · ${data.open_count || 0} open ports found so far...`);

      if (data.status === 'completed') {
        clearInterval(pollInterval);
        updateProgress(100, 'Scan complete!');
        setTimeout(() => { hideProgress(); setFormDisabled(false); renderResults(data); }, 500);
      } else if (data.status === 'failed') {
        clearInterval(pollInterval);
        showError(data.error || 'Scan failed.');
      }
    } catch (_) { /* retry silently */ }
  }, 1600);
}

// ─── Cancel ──────────────────────────────────────
function cancelScan() {
  isCancelled = true;
  clearInterval(pollInterval);
  hideProgress();
  setFormDisabled(false);
}

// ─── Render Results ───────────────────────────────
function renderResults(data) {
  const panel   = document.getElementById('resultsPanel');
  const meta    = document.getElementById('resultsMeta');
  const actions = document.getElementById('resultsActions');
  const list    = document.getElementById('portsList');

  meta.innerHTML = `
    <strong>${data.open_count}</strong> open ports on
    <strong style="color:var(--text)">${data.target}</strong>
    &nbsp;·&nbsp; ${data.total_ports} scanned
    &nbsp;·&nbsp; ${(data.duration || 0).toFixed(1)}s
  `;

  actions.innerHTML = `
    <a href="/reports/${data.job_id}/csv/" class="export-btn">↓ CSV</a>
    <a href="/reports/${data.job_id}/pdf/" class="export-btn">↓ PDF</a>
    <a href="/scan/${data.job_id}/result/" class="export-btn">Full Report →</a>
  `;

  list.innerHTML = '';

  if (!data.open_ports?.length) {
    list.innerHTML = '<div class="no-ports">No open ports found in the scanned range.</div>';
  } else {
    data.open_ports.forEach((p, i) => {
      const row = document.createElement('div');
      row.className = 'port-row';
      row.style.animationDelay = `${i * 35}ms`;

      const hasBanner = !!p.banner;
      row.innerHTML = `
        <div class="port-row-top">
          <span class="port-num">${p.port}</span>
          <span class="port-proto">${(p.protocol || 'tcp').toUpperCase()}</span>
          <span class="port-icon-badge">${p.icon || '❓'}</span>
          <div class="port-info">
            <div class="port-svc">${esc(p.service || 'Unknown')}</div>
            ${p.service_version ? `<div class="port-ver">${esc(p.service_version)}</div>` : ''}
          </div>
          ${p.response_time_ms ? `<span class="port-ms">${p.response_time_ms.toFixed(1)} ms</span>` : ''}
          ${hasBanner ? `<button class="port-banner-toggle" onclick="toggleBanner(this)">banner</button>` : ''}
        </div>
        ${hasBanner ? `<pre class="port-banner-box">${esc(p.banner.substring(0, 300))}</pre>` : ''}
      `;
      list.appendChild(row);
    });
  }

  panel.style.display = 'block';
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function toggleBanner(btn) {
  const box = btn.closest('.port-row').querySelector('.port-banner-box');
  if (!box) return;
  const open = box.style.display === 'block';
  box.style.display = open ? 'none' : 'block';
  btn.textContent = open ? 'banner' : 'hide';
}

// ─── UI Helpers ───────────────────────────────────
function setFormDisabled(disabled) {
  const btn   = document.getElementById('scanBtn');
  const input = document.getElementById('targetInput');
  if (btn)   btn.disabled = disabled;
  if (input) input.disabled = disabled;
  const form = document.getElementById('scanForm');
  if (form)  form.style.opacity = disabled ? '0.6' : '1';
}

function showProgress() {
  const p = document.getElementById('progressPanel');
  if (p) p.style.display = 'block';
}
function hideProgress() {
  const p = document.getElementById('progressPanel');
  if (p) p.style.display = 'none';
  const form = document.getElementById('scanForm');
  if (form) form.style.opacity = '1';
}
function updateProgress(pct, label) {
  const fill  = document.getElementById('progressFill');
  const pctEl = document.getElementById('progressPct');
  const meta  = document.getElementById('progressMeta');
  if (fill)  fill.style.width = pct + '%';
  if (pctEl) pctEl.textContent = pct + '%';
  if (meta)  meta.textContent = label;
}
function hideResults() {
  const p = document.getElementById('resultsPanel');
  if (p) p.style.display = 'none';
}
function showError(msg) {
  clearInterval(pollInterval);
  hideProgress();
  setFormDisabled(false);
  const hint = document.getElementById('resolveHint');
  if (hint) { hint.textContent = '✕ ' + msg; hint.style.color = 'var(--red)'; }
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}
function getCookie(name) {
  const m = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
  return m ? m[2] : null;
}
