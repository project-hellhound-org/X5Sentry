/**
 * XSSentry Web Application — Client Controller
 * Handles real-time streaming AI chat, scan controls, attack surface visualizer,
 * form submission studio, and vulnerability vault management.
 */

// Global State
const appState = {
  targetUrl: '',
  currentView: 'cockpit',
  findings: [],
  endpoints: [],
  forms: [],
  isAgentRunning: false,
};

// DOM Elements
const elements = {
  targetInput: document.getElementById('targetInput'),
  btnSetTarget: document.getElementById('btnSetTarget'),
  targetStatusPill: document.getElementById('targetStatusPill'),
  targetStatusText: document.getElementById('targetStatusText'),
  navItems: document.querySelectorAll('.nav-item'),
  viewSections: document.querySelectorAll('.view-section'),
  chatMessages: document.getElementById('chatMessages'),
  chatInput: document.getElementById('chatInput'),
  btnSendChat: document.getElementById('btnSendChat'),
  valEndpoints: document.getElementById('valEndpoints'),
  valForms: document.getElementById('valForms'),
  valPayloads: document.getElementById('valPayloads'),
  valFindings: document.getElementById('valFindings'),
  badgeFindings: document.getElementById('badgeFindings'),
  cockpitLogs: document.getElementById('cockpitLogs'),
  endpointsTableBody: document.getElementById('endpointsTableBody'),
  findingsList: document.getElementById('findingsList'),
  // Form studio
  formUrlInput: document.getElementById('formUrlInput'),
  formViewUrlInput: document.getElementById('formViewUrlInput'),
  formFieldInput: document.getElementById('formFieldInput'),
  formPayloadInput: document.getElementById('formPayloadInput'),
  btnSubmitForm: document.getElementById('btnSubmitForm'),
  formResultBox: document.getElementById('formResultBox'),
  // Live logs
  liveTerminalLogs: document.getElementById('liveTerminalLogs'),
};

// ═══════════════════════════════════════════════════════════════════
// INITIALIZATION & EVENT LISTENERS
// ═══════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupTargetBar();
  setupChat();
  setupFormStudio();
  setupQuickActions();
  setupRippleEffect();

  // Initial Status Check
  fetchStatus();
  fetchFindings();
  fetchLogs();

  // Polling intervals
  setInterval(fetchStatus, 4000);
  setInterval(fetchLogs, 3000);
});

// ═══════════════════════════════════════════════════════════════════
// RIPPLE EFFECT — Instant tactile feedback on button clicks
// ═══════════════════════════════════════════════════════════════════
function setupRippleEffect() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button, .action-card, .chip, .nav-item');
    if (!btn) return;

    // Ensure the element has relative/absolute positioning for the ripple
    const computed = getComputedStyle(btn);
    if (computed.position === 'static') {
      btn.style.position = 'relative';
    }
    if (computed.overflow !== 'hidden') {
      btn.style.overflow = 'hidden';
    }

    const ripple = document.createElement('span');
    ripple.className = 'ripple-effect';
    const rect = btn.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    ripple.style.width = ripple.style.height = `${size}px`;
    ripple.style.left = `${e.clientX - rect.left - size / 2}px`;
    ripple.style.top = `${e.clientY - rect.top - size / 2}px`;
    btn.appendChild(ripple);

    // Remove after animation completes
    ripple.addEventListener('animationend', () => ripple.remove());
  });
}

// Navigation Handling
function setupNavigation() {
  elements.navItems.forEach((item) => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const targetView = item.getAttribute('data-view');
      switchView(targetView);
    });
  });
}

function switchView(viewName) {
  appState.currentView = viewName;
  elements.navItems.forEach((item) => {
    if (item.getAttribute('data-view') === viewName) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });

  elements.viewSections.forEach((sec) => {
    if (sec.id === `view-${viewName}`) {
      sec.classList.add('active');
    } else {
      sec.classList.remove('active');
    }
  });

  if (viewName === 'attack') {
    fetchAttackSurface();
  } else if (viewName === 'vault') {
    fetchFindings();
  }
}

// ═══════════════════════════════════════════════════════════════════
// TARGET SETTING & SYSTEM STATUS
// ═══════════════════════════════════════════════════════════════════
function setupTargetBar() {
  elements.btnSetTarget.addEventListener('click', () => {
    const url = elements.targetInput.value.trim();
    if (url) setTarget(url);
  });

  elements.targetInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const url = elements.targetInput.value.trim();
      if (url) setTarget(url);
    }
  });
}

async function setTarget(url) {
  try {
    const res = await fetch('/api/target', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (data.success) {
      appState.targetUrl = data.target;
      elements.targetInput.value = data.target;
      elements.targetStatusText.textContent = 'TARGET LOCKED';
      elements.targetStatusPill.style.color = 'var(--neon-green)';
      addLogEntry(`🎯 Target active: ${data.target}`);
      if (elements.formUrlInput && !elements.formUrlInput.value) {
        elements.formUrlInput.value = data.target;
      }
    } else {
      alert(`Error setting target: ${data.error || 'Invalid target'}`);
    }
  } catch (err) {
    console.error('Target setting failed:', err);
  }
}

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    if (data.target_url) {
      appState.targetUrl = data.target_url;
      if (!elements.targetInput.value) elements.targetInput.value = data.target_url;
      elements.targetStatusText.textContent = 'TARGET LOCKED';
    } else {
      elements.targetStatusText.textContent = 'NO TARGET';
    }

    if (elements.valEndpoints) elements.valEndpoints.textContent = data.endpoints_count || 0;
    if (elements.valForms) elements.valForms.textContent = data.forms_count || 0;
    if (elements.valFindings) elements.valFindings.textContent = data.findings_count || 0;
    if (elements.badgeFindings) elements.badgeFindings.textContent = data.findings_count || 0;
  } catch (err) {
    console.error('Status check error:', err);
  }
}

// ═══════════════════════════════════════════════════════════════════
// AI SENTRY CHAT (WITH REAL-TIME SSE STREAMING)
// ═══════════════════════════════════════════════════════════════════
function setupChat() {
  elements.btnSendChat.addEventListener('click', sendChatMessage);
  elements.chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendChatMessage();
  });

  // Quick Chips
  document.querySelectorAll('.chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      elements.chatInput.value = chip.getAttribute('data-prompt');
      sendChatMessage();
    });
  });
}

async function sendChatMessage() {
  const text = elements.chatInput.value.trim();
  if (!text || appState.isAgentRunning) return;

  elements.chatInput.value = '';
  appendUserMessage(text);

  // Check for client-side local slash command
  if (text.startsWith('/view ')) {
    const v = text.split(' ')[1];
    switchView(v);
    return;
  }

  appState.isAgentRunning = true;
  elements.btnSendChat.disabled = true;
  elements.btnSendChat.textContent = 'Thinking...';

  // Create empty agent message bubble for streaming
  const agentMsgObj = appendAgentMessage();

  try {
    const url = `/api/chat/stream?prompt=${encodeURIComponent(text)}`;
    const eventSource = new EventSource(url);

    eventSource.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);

        if (data.type === 'status') {
          agentMsgObj.setStatus(data.message);
        } else if (data.type === 'tool_call') {
          agentMsgObj.addToolCall(data.name, data.args);
        } else if (data.type === 'tool_result') {
          agentMsgObj.updateToolResult(data.name, data.result);
        } else if (data.type === 'response') {
          agentMsgObj.appendResponse(data.text);
        } else if (data.type === 'error') {
          agentMsgObj.showError(data.message);
        } else if (data.type === 'done') {
          eventSource.close();
          finishChat();
        }
      } catch (parseErr) {
        console.error('SSE JSON parse error:', parseErr);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      finishChat();
    };
  } catch (err) {
    agentMsgObj.showError(err.message);
    finishChat();
  }
}

function finishChat() {
  appState.isAgentRunning = false;
  elements.btnSendChat.disabled = false;
  elements.btnSendChat.textContent = 'Send';
  fetchStatus();
}

function appendUserMessage(text) {
  const msgDiv = document.createElement('div');
  msgDiv.className = 'message user';
  msgDiv.innerHTML = `
    <div class="avatar">👤</div>
    <div class="message-bubble">${escapeHtml(text)}</div>
  `;
  elements.chatMessages.appendChild(msgDiv);
  elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
}

function appendAgentMessage() {
  const msgDiv = document.createElement('div');
  msgDiv.className = 'message agent';
  msgDiv.innerHTML = `
    <div class="avatar">🤖</div>
    <div class="message-bubble">
      <div class="agent-status" style="font-family: var(--font-mono); font-size: 11px; color: var(--neon-cyan); margin-bottom: 6px;">Analyzing request...</div>
      <div class="agent-tools"></div>
      <div class="agent-text"></div>
    </div>
  `;
  elements.chatMessages.appendChild(msgDiv);
  elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;

  const statusEl = msgDiv.querySelector('.agent-status');
  const toolsEl = msgDiv.querySelector('.agent-tools');
  const textEl = msgDiv.querySelector('.agent-text');

  return {
    setStatus: (msg) => {
      statusEl.textContent = `⚡ ${msg}`;
    },
    addToolCall: (name, args) => {
      statusEl.textContent = `⚙️ Executing tool: ${name}`;
      const pill = document.createElement('div');
      pill.className = 'tool-pill';
      pill.id = `tool-${name}`;
      pill.innerHTML = `
        <div class="tool-pill-header">
          <span>🛠️ Tool: ${escapeHtml(name)}</span>
          <span style="color: var(--neon-amber);">RUNNING</span>
        </div>
        <div class="tool-args">${escapeHtml(JSON.stringify(args || {}))}</div>
      `;
      toolsEl.appendChild(pill);
      elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
    },
    updateToolResult: (name, result) => {
      const pill = toolsEl.querySelector(`#tool-${name}`);
      if (pill) {
        pill.querySelector('.tool-pill-header span:last-child').textContent = 'DONE';
        pill.querySelector('.tool-pill-header span:last-child').style.color = 'var(--neon-green)';
      }
    },
    appendResponse: (text) => {
      statusEl.style.display = 'none';
      textEl.innerHTML = formatMarkdown(text);
      elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
    },
    showError: (err) => {
      statusEl.style.color = 'var(--neon-crimson)';
      statusEl.textContent = `❌ ${err}`;
    },
  };
}

// ═══════════════════════════════════════════════════════════════════
// QUICK ACTIONS (RECON & SPIDER)
// ═══════════════════════════════════════════════════════════════════
function setupQuickActions() {
  const btnRunRecon = document.getElementById('btnRunRecon');
  if (btnRunRecon) {
    btnRunRecon.addEventListener('click', async () => {
      if (!appState.targetUrl) {
        alert('Please set a target URL first.');
        return;
      }
      btnRunRecon.textContent = 'Scanning...';
      addLogEntry(`🔍 Initiating reconnaissance on ${appState.targetUrl}...`);
      try {
        const res = await fetch('/api/recon', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
          addLogEntry(`✅ Recon completed!`);
          fetchAttackSurface();
          switchView('attack');
        } else {
          addLogEntry(`❌ Recon failed: ${data.error}`);
        }
      } catch (err) {
        addLogEntry(`❌ Recon error: ${err.message}`);
      }
      btnRunRecon.textContent = 'Launch Recon';
    });
  }

  const btnRunSpider = document.getElementById('btnRunSpider');
  if (btnRunSpider) {
    btnRunSpider.addEventListener('click', async () => {
      if (!appState.targetUrl) {
        alert('Please set a target URL first.');
        return;
      }
      btnRunSpider.textContent = 'Crawling...';
      addLogEntry(`🕷️ Crawling ${appState.targetUrl}...`);
      try {
        const res = await fetch('/api/spider', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
          addLogEntry(`✅ Spider completed!`);
          fetchAttackSurface();
          switchView('attack');
        } else {
          addLogEntry(`❌ Spider failed: ${data.error}`);
        }
      } catch (err) {
        addLogEntry(`❌ Spider error: ${err.message}`);
      }
      btnRunSpider.textContent = 'Crawl Target';
    });
  }
}

// ═══════════════════════════════════════════════════════════════════
// ATTACK SURFACE EXPLORER
// ═══════════════════════════════════════════════════════════════════
async function fetchAttackSurface() {
  try {
    const res = await fetch('/api/attack-surface');
    const data = await res.json();
    appState.endpoints = data.endpoints || [];
    renderEndpointsTable();
  } catch (err) {
    console.error('Failed to fetch attack surface:', err);
  }
}

function renderEndpointsTable() {
  if (!elements.endpointsTableBody) return;
  elements.endpointsTableBody.innerHTML = '';

  if (appState.endpoints.length === 0) {
    elements.endpointsTableBody.innerHTML = `
      <tr>
        <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 30px;">
          No endpoints discovered yet. Run Recon or Spider from the Cockpit.
        </td>
      </tr>
    `;
    return;
  }

  appState.endpoints.forEach((ep) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><span class="method-tag ${ep.method ? ep.method.toLowerCase() : 'get'}">${ep.method || 'GET'}</span></td>
      <td style="font-family: var(--font-mono); font-size: 12px; color: var(--neon-cyan);">${escapeHtml(ep.url)}</td>
      <td><span class="brand-tag">${ep.source || 'recon'}</span></td>
      <td>
        <button class="copy-btn" onclick="sendEndpointToChat('${escapeHtml(ep.url)}')">Audit with Sentry</button>
      </td>
    `;
    elements.endpointsTableBody.appendChild(row);
  });
}

window.sendEndpointToChat = (url) => {
  switchView('chat');
  elements.chatInput.value = `Audit ${url} for XSS vulnerabilities.`;
  sendChatMessage();
};

// ═══════════════════════════════════════════════════════════════════
// STORED XSS & FORM STUDIO
// ═══════════════════════════════════════════════════════════════════
function setupFormStudio() {
  if (!elements.btnSubmitForm) return;

  elements.btnSubmitForm.addEventListener('click', async () => {
    const url = elements.formUrlInput.value.trim();
    const viewUrl = elements.formViewUrlInput.value.trim();
    const field = elements.formFieldInput.value.trim();
    const payload = elements.formPayloadInput.value.trim();

    if (!url) {
      alert('Form URL is required.');
      return;
    }

    elements.btnSubmitForm.disabled = true;
    elements.btnSubmitForm.textContent = 'Testing Stored Reflection...';
    elements.formResultBox.innerHTML = `
      <div style="font-family: var(--font-mono); font-size: 12px; color: var(--neon-cyan);">
        ⏳ Extracting CSRF tokens, submitting payload, and checking reflection...
      </div>
    `;

    try {
      const res = await fetch('/api/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          view_url: viewUrl || url,
          field: field || 'website',
          payload: payload || 'javascript:alert(1)',
        }),
      });
      const data = await res.json();
      renderFormResult(data);
    } catch (err) {
      elements.formResultBox.innerHTML = `
        <div style="color: var(--neon-crimson); font-family: var(--font-mono);">
          ❌ Submission error: ${escapeHtml(err.message)}
        </div>
      `;
    }

    elements.btnSubmitForm.disabled = false;
    elements.btnSubmitForm.textContent = '🚀 Test Form for Stored XSS';
    fetchFindings();
    fetchStatus();
  });
}

function renderFormResult(data) {
  if (!data.success) {
    elements.formResultBox.innerHTML = `
      <div style="color: var(--neon-crimson); font-family: var(--font-mono);">
        ❌ Error: ${escapeHtml(data.error || 'Test failed')}
      </div>
    `;
    return;
  }

  const res = data.result;
  const isVuln = res.stored_xss || res.is_vulnerable || res.href_injection;
  const color = isVuln ? 'var(--neon-crimson)' : 'var(--neon-green)';
  const badge = isVuln ? 'VULNERABLE (STORED XSS)' : 'SAFE / NO STORED XSS';

  elements.formResultBox.innerHTML = `
    <div style="border: 1px solid ${color}; border-radius: var(--radius-md); padding: 16px; background: rgba(0,0,0,0.4);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <span style="font-family: var(--font-mono); font-weight: 800; color: ${color}; font-size: 14px;">${badge}</span>
        <span class="brand-tag">Context: ${res.reflection_context || 'N/A'}</span>
      </div>
      <div style="font-size: 13px; margin-bottom: 8px;">
        <strong>Target Field:</strong> <code>${escapeHtml(res.target_field || 'website')}</code> |
        <strong>Payload Found:</strong> ${res.payload_found ? '✅ Yes' : '❌ No'}
      </div>
      <div style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">
        ${(res.notes || []).map((n) => `<div>👉 ${escapeHtml(n)}</div>`).join('')}
      </div>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════
// VULNERABILITY VAULT
// ═══════════════════════════════════════════════════════════════════
async function fetchFindings() {
  try {
    const res = await fetch('/api/findings');
    const data = await res.json();
    appState.findings = data.findings || [];
    renderFindings();
  } catch (err) {
    console.error('Failed to fetch findings:', err);
  }
}

function renderFindings() {
  if (!elements.findingsList) return;
  elements.findingsList.innerHTML = '';

  if (appState.findings.length === 0) {
    elements.findingsList.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); padding: 50px;">
        No vulnerabilities verified yet. Set a target and audit endpoints or forms!
      </div>
    `;
    return;
  }

  appState.findings.forEach((f) => {
    const card = document.createElement('div');
    card.className = 'finding-card';
    card.innerHTML = `
      <div class="finding-header">
        <div class="finding-title">⚡ ${escapeHtml(f.type || 'Cross-Site Scripting')}</div>
        <span class="severity-badge ${f.severity ? f.severity.toLowerCase() : 'high'}">${f.severity || 'HIGH'}</span>
      </div>
      <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 10px;">
        <strong>Location:</strong> <code style="color: var(--neon-cyan);">${escapeHtml(f.url || '')}</code>
      </div>
      <div class="poc-block">
        <code>${escapeHtml(f.payload || 'javascript:alert(1)')}</code>
        <button class="copy-btn" onclick="copyText('${escapeHtml(f.payload || '')}')">Copy PoC</button>
      </div>
      <div style="font-size: 12px; color: var(--text-muted);">
        <strong>Context:</strong> ${escapeHtml(f.context || 'HTML/Attribute reflection')}
      </div>
    `;
    elements.findingsList.appendChild(card);
  });
}

// ═══════════════════════════════════════════════════════════════════
// LIVE LOGS
// ═══════════════════════════════════════════════════════════════════
async function fetchLogs() {
  try {
    const res = await fetch('/api/logs');
    const data = await res.json();
    if (data.logs && elements.cockpitLogs) {
      elements.cockpitLogs.innerHTML = data.logs
        .slice(-30)
        .map((l) => `<div class="log-entry">${escapeHtml(l)}</div>`)
        .join('');
      elements.cockpitLogs.scrollTop = elements.cockpitLogs.scrollHeight;
    }
    if (data.logs && elements.liveTerminalLogs) {
      elements.liveTerminalLogs.innerHTML = data.logs
        .map((l) => `<div class="log-entry">${escapeHtml(l)}</div>`)
        .join('');
      elements.liveTerminalLogs.scrollTop = elements.liveTerminalLogs.scrollHeight;
    }
  } catch (err) {
    // Suppress polling error in console
  }
}

function addLogEntry(text) {
  const ts = new Date().toLocaleTimeString();
  const entry = `[${ts}] ${text}`;
  if (elements.cockpitLogs) {
    const d = document.createElement('div');
    d.className = 'log-entry';
    d.textContent = entry;
    elements.cockpitLogs.appendChild(d);
    elements.cockpitLogs.scrollTop = elements.cockpitLogs.scrollHeight;
  }
}

// ═══════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatMarkdown(text) {
  if (!text) return '';
  let md = escapeHtml(text);
  // Bold
  md = md.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  // Inline code
  md = md.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Line breaks
  md = md.replace(/\n/g, '<br/>');
  return md;
}

window.copyText = (text) => {
  navigator.clipboard.writeText(text);
  alert('PoC Payload copied to clipboard!');
};
