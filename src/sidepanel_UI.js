/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

// Global variables to track state and prevent unnecessary UI updates
let lastState = {}; // Global variable to track the current state
let isChangingPassword = false;

const cards = {
  synth: document.getElementById("card-synth"),
  synthExtra: document.getElementById("synth-extra-inputs"),
  crypto: document.getElementById("card-crypto"), // Unified card
  note: document.getElementById("card-note"),
  masterSection: document.getElementById("master-password-section"),
};

function setCryptoMode(mode) {
  const card = document.getElementById('card-crypto');
  if (card) card.dataset.mode = mode;
  masterPasswordContext = mode; // Still needed for the crypto logic
  if (typeof updateLockList === 'function') updateLockList();
}

//displays status messages in the global status area with appropriate colors based on tone (good, bad, info)
let statusTimeout = null;

function showStatusMsg(content, tone) {
  const el = document.getElementById('mainMsg');
  if (!el) return;

  const colors = {
    good: '#16a34a',
    bad: '#ef4444',
    info: 'var(--text-muted)', // Use theme-aware CSS variable
    special: '#3b82f6'
  };

  // 1. Nuclear Reset: Wipe style, classes, and timer
  if (statusTimeout) clearTimeout(statusTimeout);
  el.removeAttribute('style');
  el.className = '';

  // 2. Apply New State
  el.style.color = colors[tone] || colors.info;
  el.innerHTML = content; // Changed to innerHTML for license formatting

  // 3. Security Hook
  if (tone === 'good' && typeof lockMasterPassword === 'function') {
    lockMasterPassword();
  }

  // 4. Transient messages clear after 10s
  if ((tone === 'good' || tone === 'info') && content !== '') {
    statusTimeout = setTimeout(() => {
      el.innerHTML = '';
      el.style.color = 'var(--text-main)'; // Match info fallback
    }, 10000);
  }
}

function lockMasterPassword() {
  const input = document.getElementById('m-pass');
  const eyeOpen = document.getElementById('icon-eye-open');
  const eyeClosed = document.getElementById('icon-eye-closed');
  const toggle = document.getElementById('toggle-mpass');
  if (!input) return;
  input.type = 'password';
  if (eyeOpen) eyeOpen.style.display = 'none';
  if (eyeClosed) eyeClosed.style.display = 'none';
  if (toggle) toggle.style.pointerEvents = 'none';
}

function unlockMasterPassword() {
  const input = document.getElementById('m-pass');
  const eyeOpen = document.getElementById('icon-eye-open');
  const eyeClosed = document.getElementById('icon-eye-closed');
  const toggle = document.getElementById('toggle-mpass');
  if (!input) return;

  // Reset to password type and show the "eye open" icon
  input.type = 'password';
  if (eyeOpen) eyeOpen.style.display = 'block';
  if (eyeClosed) eyeClosed.style.display = 'none';
  if (toggle) toggle.style.pointerEvents = 'auto';
}

// Pull state immediately on load to handle the case where the side panel is opened after the page has already loaded and the agent has done its initial scan.
function getRegisteredDomain(hostname) {
  if (!hostname) return hostname;
  // normalize, drop port and trailing dot
  hostname = hostname.toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
  // IP or single-label host (localhost)
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname.indexOf(".") === -1)
    return hostname;
  // strip common www variants
  hostname = hostname.replace(/^www\d*\./, "");
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const tld = parts[parts.length - 1];
  // if TLD is 2 chars (likely ccTLD), use last 3 parts where possible
  if (tld.length === 2 && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  // default: last 2 parts
  return parts.slice(-2).join(".");
}

/**
 * Unified handler for site connection status.
 * Updates the Connect button and main message based on background script response.
 */
function handleConnectionResponse(response) {
  // PRUNED: Removed all logic related to the connect-btn element

  if (response && response.success) {
    console.log("Privacy Bar: Connection established via ActiveTab.");
    showStatusMsg("Site Connected", "info");

    if (response.state) {
      updateUI(response.state);
    }
  } else {
    console.error("Privacy Bar: Agent handshake failed.");
    showStatusMsg("Cannot access this page.", "bad");
  }
}

// ===== TAB SWITCHING LOGIC =====
let activeTabsByTabId = {}; // null = auto-detection mode
let currentActiveTab = null; // Track the actual active tab globally


function switchTab(tabName) {
  if (tabName === currentActiveTab) return;
  currentActiveTab = tabName;

  // 1. Update the manual lock and persist it
  if (window.currentTabId) {
    activeTabsByTabId[window.currentTabId] = tabName;
    chrome.storage.session.set({ [`tabUI_${window.currentTabId}`]: tabName });
  }

  // 2. Button highlight
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });

  // 3. UI Card Visibility
  ['card-synth', 'card-crypto', 'card-note', 'dropTargetCard', 'stego-image-container', 'synth-extra-inputs', 'decrypt-email-display', 'directory-card']
    .forEach(id => document.getElementById(id)?.classList.add('hidden'));

  document.getElementById('master-password-section')?.classList.remove('hidden');

  if (tabName === 'synth') {
    document.getElementById('card-synth')?.classList.remove('hidden');
    document.getElementById('synth-extra-inputs')?.classList.remove('hidden');
    masterPasswordContext = 'synth';
  } else if (tabName === 'crypto') {
    document.getElementById('card-crypto')?.classList.remove('hidden');
    document.getElementById('dropTargetCard')?.classList.remove('hidden');
    document.getElementById('stego-image-container')?.classList.remove('hidden');
    document.getElementById('decrypt-email-display')?.classList.remove('hidden');
  } else if (tabName === 'notes') {
    document.getElementById('card-note')?.classList.remove('hidden');
    masterPasswordContext = 'notes';
    if (typeof enterNotesMode === 'function') enterNotesMode(window.currentHost);
  }
}

/**
 * RELOAD WATCHER: 
 * Re-triggers injection if the browser tab reloads while the panel is open
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Silent exit if it's a restricted system page
  if (isRestrictedUrl(tab.url)) return;

  if (changeInfo.status === 'complete') {
    console.log("Active tab reload detected. Re-triggering PANEL_ACTIVE...");

    chrome.runtime.sendMessage({
      action: "PANEL_ACTIVE",
      tabId: tabId
    }, handleConnectionResponse);
  }
});

// function to safely initialize the encrypt card once
function setupCryptoCardListeners() {
  const lockList = document.getElementById('lockList');
  if (lockList) {
    // Remove first to avoid double-binding if updateUI runs multiple times
    lockList.removeEventListener('change', updateRecipientStatus);
    lockList.addEventListener('change', updateRecipientStatus);
  }

  const toolBar = document.getElementById('toolBar');
  if (toolBar) {
    toolBar.addEventListener('click', (e) => {
      const cmdBtn = e.target.closest('.intLink');
      if (cmdBtn) {
        const cmd = cmdBtn.getAttribute('data-command');
        const box = document.getElementById('mainBox');
        if (box) {
          box.focus();
          document.execCommand(cmd, false, null);
          setTimeout(updateToolbarState, 10);
        }
      }
    });
  }
}

// 2. Robust State Checker
function updateToolbarState() {
  const buttons = document.querySelectorAll('#toolBar .intLink');
  buttons.forEach(btn => {
    const cmd = btn.getAttribute('data-command');
    if (cmd) {
      try {
        if (document.queryCommandState(cmd)) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      } catch (e) {
        // Some commands might not support queryCommandState in all contexts
      }
    }
  });
}

// 3. Track state via multiple events inside the box
const box = document.getElementById('mainBox');
if (box) {
  ['keyup', 'mouseup', 'focus'].forEach(evt => {
    box.addEventListener(evt, updateToolbarState);
  });
}

// Also keep the global selection listener as a backup
document.addEventListener('selectionchange', () => {
  if (document.activeElement.id === 'mainBox') {
    updateToolbarState();
  }
});

let masterPwdTimeout = null;

async function updateUI(state) {
  if (state) lastState = state;
  const s = lastState;

  // Restore MK from session if it exists
  chrome.storage.session.get("masterPwd", (res) => {
    if (res.masterPwd) {
      const mpInput = document.getElementById("m-pass");
      // If a cached key exists but the field is empty (e.g. on reload), restore it
      if (mpInput && !mpInput.value) {
        mpInput.value = res.masterPwd;
        startMasterPwdTimeout(); // Resume the heartbeat
      }
    }
  });

  // 1. Synchronous Context Acquisition
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const currentTabId = tab?.id;
  const currentUrl = tab?.url || "";
  if (!currentTabId) return;

  // Cache the ID globally so click listeners can use it synchronously
  window.currentTabId = currentTabId;

  // --- CONNECT SITE LOGIC ---
  const connectBtn = document.getElementById('connect-btn');
  const mainMsg = document.getElementById('mainMsg');
  if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('about:')) {
    if (connectBtn) connectBtn.classList.add('hidden');
    if (mainMsg) mainMsg.textContent = "Privacy Bar is restricted on system pages.";
    return;
  }

  // 2. DATA SYNC
  if (s && s.host) {
    currentHost = getRegisteredDomain(s.host);
    window.currentHost = currentHost;
    loadHostData(currentHost);
  }

  // 3. TAB DETERMINATION (Manual > File Mode > Auto)
  let targetTab = null;
  const manualLock = activeTabsByTabId[currentTabId];

  if (manualLock) {
    targetTab = manualLock;
  } else if (window.manualModeTabId === currentTabId) {
    targetTab = 'crypto';
  } else {
    const hasPasswords = s.hasPasswords || (s.passwordCount > 0);
    const hasBlobs = s.hasCrypto || false;
    const hasTextAreas = s.hasLargeInputField || false;
    if (hasPasswords) targetTab = 'synth';
    else if (hasTextAreas || hasBlobs) targetTab = 'crypto';
    else targetTab = 'notes';
  }

  // 4. EXECUTE
  if (targetTab !== currentActiveTab) {
    switchTab(targetTab);
  }

  if (targetTab === 'crypto') {
    setCryptoMode(s.hasCrypto ? 'decrypt' : 'encrypt');
  }
  if (typeof updateFolderKeyUI === 'function') updateFolderKeyUI();
}

function resetDecryptButtonStyle() {
  const decryptBtn = document.getElementById("do-decrypt-selection");
  if (decryptBtn) {
    decryptBtn.style.background = "";
    decryptBtn.style.color = "";
  }
}

/**
 * Updates Synth-related UI elements.
 */
function updateSynthUI(synthData) {
  const serial = document.getElementById("serial");
  const allowed = document.getElementById("allowed-chars");
  const limit = document.getElementById("length-limit");
  const userId = document.getElementById("user-id"); // The new field

  if (serial && document.activeElement !== serial) {
    serial.value = synthData.serial || "";
  }
  if (allowed && document.activeElement !== allowed) {
    allowed.value = synthData.allowedChars || "";
  }
  if (limit && document.activeElement !== limit) {
    limit.value = synthData.lengthLimit || "";
  }
  // Populate the User ID
  if (userId && document.activeElement !== userId) {
    userId.value = synthData.userID || "";
  }
}

/**
 * Updates Crypt-related UI elements.
 */
function updateCryptUI(cryptData) {
  const emailField = document.getElementById("user-email");
  if (emailField) {
    // Focus Guard: Do not overwrite the value if the user is currently typing
    if (document.activeElement !== emailField) {
      emailField.value = cryptData.email || "";
    }
  }
}

// ===== SERIAL etc STORAGE =====
/**
 * Loads all host-specific data (synth & crypt) and updates the UI.
 */
function loadHostData(host) {
  if (!host) return;

  chrome.storage.sync.get([host], (result) => {
    const hostData = result[host] || {};
    const synth = hostData.synth || {};
    const crypt = hostData.crypt || {};

    // Update Synth UI
    updateSynthUI(synth);

    // Update Decrypt UI
    updateCryptUI(crypt);

    // Notify DirectoryEditor of host change
    if (
      typeof DirectoryEditor !== "undefined" &&
      typeof DirectoryEditor.setHost === "function"
    ) {
      DirectoryEditor.setHost(host);
    }
  });
}

function updateRecipientStatus() {
  const lockList = document.getElementById('lockList');
  const statusBox = document.getElementById('composeRecipientsBox');

  if (!lockList || !statusBox) return;

  // Get the text of all selected options
  const selected = Array.from(lockList.selectedOptions).map(o => o.textContent);

  if (selected.length === 0) {
    statusBox.textContent = "Nobody! (Shared Key mode)";
  } else {
    // Join names with commas for the display
    statusBox.textContent = selected.join(', ');
  }
}

/**
 * Unified Saver: Pulls identity from the Synthesis tab and manages the vault.
 */
function saveHostData(host, newVaultCipher = undefined) {
  if (!host) return;

  chrome.storage.sync.get(host, (data) => {
    const item = data[host] || {};
    const synth = item.synth || {};

    // Pulls from the Synthesis tab ID #user-id
    synth.userID = document.getElementById("user-id").value.trim();
    synth.serial = document.getElementById("serial").value.trim();
    synth.allowedChars = document.getElementById("allowed-chars").value.trim();
    synth.lengthLimit = document.getElementById("length-limit").value.trim();

    item.synth = synth;

    if (newVaultCipher !== undefined) {
      item.crypt = item.crypt || {};
      item.crypt.pwd = newVaultCipher;
    }

    chrome.storage.sync.set({ [host]: item }, () => {
      updateVaultStatus();
    });
  });
}

let hashiliTimer = null;

/// ===== Master Key STRENGTH & HASHILI =====
document.getElementById("m-pass").addEventListener("input", (e) => {
  const pwd = e.target.value;
  const hashEl = document.getElementById("hashili");
  const fill = document.getElementById("strength-fill");

  if (hashiliTimer) clearTimeout(hashiliTimer);

  if (!pwd.trim()) {
    fill.style.width = "0%";
    hashEl.textContent = "";
    unlockMasterPassword();
    return;
  }

  // Update strength bar
  const entropy =
    typeof entropyCalc === "function" ? entropyCalc(pwd) : pwd.length * 4;
  const percentage = Math.min(100, (entropy / 80) * 100);
  fill.style.width = percentage + "%";
  fill.style.background =
    percentage < 30 ? "#ef4444" : percentage < 70 ? "#f59e0b" : "#22c55e";

  // Debounced Hashili
  hashiliTimer = setTimeout(() => {
    if (typeof makeHashili === "function") {
      hashEl.textContent = makeHashili(pwd);
    }
  }, 1000);
});

// Enter key handling
document.getElementById("m-pass").addEventListener("keypress", (e) => {
  if (e.key === "Enter") {
    if (masterPasswordContext === "synth") {
      document.getElementById("do-synth").click();
    } else if (masterPasswordContext === "encrypt") {
      document.getElementById("do-decrypt-selection").click();
    } else if (masterPasswordContext === "notes") {
      unlockAndDecryptNote();
    }
  }
});

// ===== TOGGLE Master Key VISIBILITY =====
document.getElementById("toggle-mpass").addEventListener("click", () => {
  const input = document.getElementById("m-pass");
  const eyeOpen = document.getElementById("icon-eye-open");
  const eyeClosed = document.getElementById("icon-eye-closed");

  if (input.type === "password") {
    input.type = "text";
    eyeOpen.style.display = "none";
    eyeClosed.style.display = "block";
  } else {
    input.type = "password";
    eyeOpen.style.display = "block";
    eyeClosed.style.display = "none";
  }
});

// Add a way to open the directory
function openDirectory() {
  DirectoryEditor.open();
}

setupCryptoCardListeners();  //formatting buttons etc.

window.updateLockList = function () {
  const lockList = document.getElementById('lockList');
  if (!lockList) return;

  // FOCUS GUARD: If the user is currently interacting with the list, don't rebuild it.
  // This prevents the "constant update" bug on dynamic sites like Yahoo Mail.
  if (document.activeElement === lockList) return;

  const modeSelect = document.getElementById('mode-select');
  const currentMode = modeSelect ? modeSelect.value : 'signed';
  const isPQMode = (currentMode === 'pq-signed' || currentMode === 'pq-anon');

  const selectedValues = Array.from(lockList.selectedOptions).map(o => o.value);

  chrome.storage.sync.get(['locDir', currentHost], (result) => {
    const locDir = result.locDir || {};
    lockList.innerHTML = '';

    // 1. Me Option
    const meOption = document.createElement('option');
    meOption.value = "me";
    meOption.textContent = "Me";
    if (selectedValues.includes("me")) meOption.selected = true;
    lockList.appendChild(meOption);

    const groups = [];
    const individuals = [];

    for (const [name, value] of Object.entries(locDir)) {
      if (name.startsWith('$')) continue;

      // --- THE STRUCTURAL PQ FILTER ---
      if (isPQMode) {
        const isObject = (typeof value === 'object' && value !== null);
        const isGroup = isObject ? value.lock?.includes(',') : value?.includes(',');
        const hasPQLock = isObject && value.pqlock;

        // If it's a PQ mode, only show if it's a Group list OR has a pqlock key
        if (!isGroup && !hasPQLock) {
          continue;
        }
      }

      // Extract the display value for the option
      let valString = (typeof value === 'object' && value !== null) ? value.lock : value;
      if (!valString) continue;

      const isGroup = valString.includes(',');
      const entry = { name, value: valString };

      if (isGroup) {
        groups.push(entry);
      } else {
        individuals.push(entry);
      }
    }

    // 4. Sort and Append Groups
    groups.sort((a, b) => a.name.localeCompare(b.name));
    groups.forEach(group => {
      const option = document.createElement('option');
      option.value = group.value;
      option.textContent = `=${group.name}=`;
      if (selectedValues.includes(group.value)) option.selected = true;
      lockList.appendChild(option);
    });

    // 5. Sort and Append Individuals
    individuals.sort((a, b) => a.name.localeCompare(b.name));
    individuals.forEach(indiv => {
      const option = document.createElement('option');
      option.value = indiv.value;
      option.textContent = indiv.name;
      if (selectedValues.includes(indiv.value)) option.selected = true;
      lockList.appendChild(option);
    });
  });
};

window.updateLockList = updateLockList; // Expose globally if needed

// Listen for mode changes to trigger the PQ/Classic filter
const modeSelect = document.getElementById('mode-select');

if (modeSelect) {
  modeSelect.addEventListener('change', () => {
    // Refresh the list immediately when the user toggles modes
    if (typeof window.updateLockList === 'function') {
      window.updateLockList();
    }
  });
}

function updateRecipientStatus() {
  const lockList = document.getElementById('lockList');
  const recipientDisplay = document.getElementById('composeRecipientsBox');
  if (!lockList || !recipientDisplay) return;

  const selectedOptions = Array.from(lockList.selectedOptions).filter(opt => opt.value);

  if (selectedOptions.length === 0) {
    recipientDisplay.textContent = "Nobody! (Shared Key mode)";
    recipientDisplay.style.color = "#666";
  } else {
    // Use textContent to show "Me" and "=Groups=" exactly as they appear in the list
    const names = selectedOptions.map(opt => opt.textContent);
    recipientDisplay.textContent = names.join(", ");
    recipientDisplay.style.color = "#2e7d32"; // Success Green
  }
}

document.getElementById("open-directory-btn").addEventListener("click", () => {
  DirectoryEditor.setMode("locDir"); // Force global directory mode
  DirectoryEditor.open();
});

chrome.runtime.onMessage.addListener((request) => {
  if (request.action === "SIDE_PANEL_URL_SYNC") {
    console.log("Received URL from Background Bridge:", request.url);

    window.currentTabUrl = request.url;
    window.currentTabId = request.tabId;

    // Proceed directly to requesting agent status
    if (typeof requestAgentStatus === 'function') {
      requestAgentStatus(request.tabId);
    }
  }

  if (request.type === "STATE_UPDATE") {
    updateUI(request.state);
  }

  if (request.action === "SESSION_WIPED") {
    const pwdInput = document.getElementById('m-pass');
    if (pwdInput) {
      pwdInput.value = "";
      unlockMasterPassword();
      document.getElementById('strength-fill').style.width = '0%';
      document.getElementById('hashili').textContent = '';
      showStatusMsg("Session timed out. Keys cleared.", "special");
    }
  }

  if (request.type === "LOAD_STEGO_IMAGE") {
    const preview = document.getElementById('stego-image-preview');
    const placeholder = document.getElementById('stego-placeholder');
    if (!preview || !placeholder) return;

    const processImage = (dataUrl) => {
      preview.onload = () => {
        const isPng = dataUrl.startsWith('data:image/png');
        const pngRadio = document.getElementById('stego-format-png');
        const jpgRadio = document.getElementById('stego-format-jpg');

        if (pngRadio && jpgRadio) {
          pngRadio.checked = isPng;
          jpgRadio.checked = !isPng;
        }

        if (typeof window.updateStegoCapacity === 'function') {
          window.updateStegoCapacity(preview, isPng);
        }
      };

      // Convert DataURL to Uint8Array immediately and store globally, for camo feature
      fetch(dataUrl).then(res => res.arrayBuffer()).then(buf => {
        window.currentCoverBytes = new Uint8Array(buf);
      });

      preview.src = dataUrl;
      preview.style.display = 'block';
      placeholder.style.display = 'none';
      switchTab("crypto");
      showStatusMsg("Image loaded from page", "info");
    };

    if (request.dataUrl) {
      processImage(request.dataUrl);
    } else if (request.url) {
      fetch(request.url)
        .then(r => r.blob())
        .then(blob => {
          const reader = new FileReader();
          reader.onload = (e) => processImage(e.target.result);
          reader.readAsDataURL(blob);
        })
        .catch(() => showStatusMsg("CORS error: cannot load image", "bad"));
    }
    return;
  }

  if (request.type === "BLOB_CLICKED") {
    // 1. Inject blob into the unified box
    const box = document.getElementById("mainBox");
    if (box) {
      box.textContent = request.blob.raw;

      //auto-decrypt
      const decryptBtn = document.getElementById('do-decrypt-selection');
      if (decryptBtn && document.getElementById('auto-process-check').checked) decryptBtn.click();
    }

    // 2. Set mode to decrypt and switch to the Crypto tab
    setCryptoMode("decrypt");
    switchTab("crypto");
    activeTab = null; // Reset to null so auto-detection can resume if page changes, 
    // or keep as "crypto" if you want it to stick.

    showStatusMsg(`Loaded blob of type: ${request.blob.type}`, "info");
  }
});

// --- content script injection ---

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const activeTab = tabs[0];
  if (!activeTab || !activeTab.id) return;

  // 1. Guard against restricted pages immediately
  if (activeTab.url?.startsWith(chrome.runtime.getURL("")) ||
    activeTab.url?.startsWith("chrome://") ||
    activeTab.url?.startsWith("about:")) {
    return;
  }

  // 2. The Safe Message Handshake
  chrome.tabs.sendMessage(activeTab.id, { type: "GET_CURRENT_STATE" }, (response) => {
    // We MUST check lastError here to stop the "Unchecked" console error
    if (chrome.runtime.lastError) {
      console.log("Privacy Bar: Agent not found. Requesting injection...");

      // If agent is missing, tell the background script to push it
      chrome.runtime.sendMessage({
        action: "PANEL_ACTIVE",
        tabId: activeTab.id
      }, (res) => handleConnectionResponse(res));
      return;
    }

    if (response) {
      updateUI(response);
    }
  });
});

// ===== Master Key TIMEOUT (5 minutes) =====

/**
 * RE-ENGINEERED: Unified Security Heartbeat.
 * Sets the global MK session and triggers the background alarm.
 */
function startMasterPwdTimeout() {
  const mpInput = document.getElementById('m-pass');
  const masterPwd = mpInput?.value.trim();

  if (!masterPwd) return;

  // 1. Sync MK to session storage for "Everything" (Synth, Crypto, Notes)
  chrome.storage.session.set({ "masterPwd": masterPwd });

  // 2. Set/Reset the background security alarm (5-minute window)
  chrome.alarms.create("SPAlarm", { delayInMinutes: 5 });
}

// Reset the timeout on any meaningful UI interaction
['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(eventType => {
  document.addEventListener(eventType, () => {
    if (typeof startMasterPwdTimeout === 'function') {
      startMasterPwdTimeout();
    }
  }, { passive: true });
});

/**
 * Caches the Master Key in session storage and secures the UI.
 */
function cacheMasterKey(masterPwd) {
  if (!masterPwd) return;

  // 1. Persist to session storage for the browser session
  chrome.storage.session.set({ "masterPwd": masterPwd });
  
  // 2. Trigger the timeout/wipe alarm
  chrome.alarms.create("SPAlarm", { delayInMinutes: 5 });

  // 3. Secure the UI input field
  const mpInput = document.getElementById("m-pass");
  if (mpInput) {
    mpInput.type = "password";
    const toggleIcon = document.getElementById("toggle-mpass");
    if (toggleIcon) toggleIcon.style.visibility = 'hidden';
  }
}

// === TOOLBAR WIRING ===

// Dropdowns
document.getElementById('formatBlock')?.addEventListener("change", function () {
  formatDoc('formatBlock', this[this.selectedIndex].value);
  this.selectedIndex = 0;
});

document.getElementById('fontName')?.addEventListener("change", function () {
  formatDoc('fontName', this[this.selectedIndex].value);
  this.selectedIndex = 0;
});

document.getElementById('fontSize')?.addEventListener("change", function () {
  formatDoc('fontSize', this[this.selectedIndex].value);
  this.selectedIndex = 0;
});

document.getElementById('foreColor')?.addEventListener("change", function () {
  formatDoc('foreColor', this[this.selectedIndex].value);
  this.selectedIndex = 0;
});

// Icon buttons
const toolBar2 = document.getElementById('toolBar2');
if (toolBar2) {
  toolBar2.children[0]?.addEventListener("click", () => formatDoc('bold'));
  toolBar2.children[1]?.addEventListener("click", () => formatDoc('italic'));
  toolBar2.children[2]?.addEventListener("click", () => formatDoc('underline'));
  toolBar2.children[3]?.addEventListener("click", () => formatDoc('strikethrough'));
  toolBar2.children[4]?.addEventListener("click", () => formatDoc('undo'));
  toolBar2.children[5]?.addEventListener("click", () => formatDoc('redo'));
  toolBar2.children[6]?.addEventListener("click", () => formatDoc('justifyleft'));
  toolBar2.children[7]?.addEventListener("click", () => formatDoc('justifycenter'));
  toolBar2.children[8]?.addEventListener("click", () => formatDoc('insertorderedlist'));
  toolBar2.children[9]?.addEventListener("click", () => formatDoc('insertunorderedlist'));
  toolBar2.children[10]?.addEventListener("click", () => {
    const url = prompt('Enter URL:', 'https://');
    if (url && url !== '' && url !== 'https://') formatDoc('createlink', url);
  });
  toolBar2.children[11]?.addEventListener("click", () => formatDoc('removeFormat'));
}

// File inputs
document.getElementById('imgFile')?.addEventListener('change', loadImage);
document.getElementById('imgFile')?.addEventListener('click', function () { this.value = ''; });

document.getElementById('mainFile')?.addEventListener('change', loadFile);
document.getElementById('mainFile')?.addEventListener('click', function () { this.value = ''; });

// Download all button
document.getElementById('downloadAllBtn')?.addEventListener("click", downloadAllFiles);

// Update toolbar state on selection change
document.getElementById('mainBox')?.addEventListener('mouseup', updateToolbarState);
document.getElementById('mainBox')?.addEventListener('keyup', updateToolbarState);

/**
 * Executes a document.execCommand and updates toggle button states
 */
function formatDoc(command, value = null) {
  document.execCommand(command, false, value);
  document.getElementById('mainBox')?.focus();

  // Update toggle button states
  updateToolbarState();
}


/**
 * Updates the visual state of toggle buttons based on current selection
 */
function updateToolbarState() {
  const toolBar2 = document.getElementById('toolBar2');
  if (!toolBar2) return;

  // Map of commands to button indices
  const toggleButtons = [
    { index: 0, command: 'bold' },
    { index: 1, command: 'italic' },
    { index: 2, command: 'underline' },
    { index: 3, command: 'strikethrough' },
    { index: 6, command: 'justifyleft' },
    { index: 7, command: 'justifycenter' },
    { index: 8, command: 'insertorderedlist' },
    { index: 9, command: 'insertunorderedlist' }
  ];

  toggleButtons.forEach(btn => {
    const button = toolBar2.children[btn.index];
    if (button && button.classList.contains('intLink')) {
      const isActive = document.queryCommandState(btn.command);
      button.style.backgroundColor = isActive ? '#b0d4ff' : '';
    }
  });
}

// Also update state when user clicks in the compose box
document.getElementById('mainBox')?.addEventListener('mouseup', updateToolbarState);
document.getElementById('mainBox')?.addEventListener('keyup', updateToolbarState);

/**
 * Handles image selection and inserts as a visible image wrapped in a download anchor
 */
function loadImage(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    const dataURL = e.target.result;

    // Insert just the image with the filename stored in alt and title
    const imgTag = `<img src="${dataURL}" alt="${file.name}" title="${file.name}" style="max-width:100%;" /> `;

    document.execCommand('insertHTML', false, imgTag);
    //    setStatus(`Image "${file.name}" loaded.`);
    showStatusMsg(`Image "${file.name}" loaded.`, "info");
  };

  reader.readAsDataURL(file);
  event.target.value = ''; // Reset input so same file can be loaded again
}

function loadFile(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    const dataURL = e.target.result;

    // Create anchor element for file download
    const anchor = `<a href="${dataURL}" download="${file.name}" title="Click to download ${file.name}" style="padding:5px; background:#fff8dc; border:1px solid #ccc;">[File: ${file.name}]</a> `;

    document.execCommand('insertHTML', false, anchor);
  };

  reader.readAsDataURL(file);
}

/**
 * Downloads all embedded files from the compose box
 */
function downloadAllFiles() {
  const box = document.getElementById('mainBox');
  const anchors = box.querySelectorAll('a[href^="data:"]');

  if (anchors.length === 0) {
    //    setStatus("No files found to download.");
    showStatusMsg("No files found to download.", "bad");
    return;
  }

  let downloaded = 0;
  anchors.forEach((anchor, index) => {
    // Stagger downloads to prevent browser blocking
    setTimeout(() => {
      const link = document.createElement('a');
      link.href = anchor.href;
      link.download = anchor.download || `file_${index + 1}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      downloaded++;
      if (downloaded === anchors.length) {
        showStatusMsg(`Downloaded ${downloaded} file(s).`, "info");
      }
    }, index * 300); // 300ms delay between each download
  });

  showStatusMsg(`Downloading ${anchors.length} file(s)...`, "info");
}

document.getElementById('decryptFileBtn')?.addEventListener('click', () => {
  document.getElementById('pbxFileInput').click();
});

const dropTarget = box; // Make the entire compose box a drop target for better UX

if (dropTarget) {
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropTarget.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
    }, false);
  });

  dropTarget.addEventListener('dragenter', () => {
    dropTarget.classList.add('drag-over');
    // Check if a Folder Key is active to apply the green style
    if (window.activeFolderKey) {
      dropTarget.classList.add('folder-active');
    } else {
      dropTarget.classList.remove('folder-active');
    }
  });

  dropTarget.addEventListener('dragleave', () => {
    dropTarget.classList.remove('drag-over');
  });

  dropTarget.addEventListener('drop', (e) => {
    setTimeout(function () { dropTarget.classList.remove('drag-over') }, 10);

    //pro feature
    if (!window.checkProGate()) return;

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleMainBoxFiles(files);
    }
  });
}

// Main handler for dropped files
async function handleMainBoxFiles(files) {
  const masterPwd = document.getElementById('m-pass')?.value.trim();

  try {
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const fileName = file.name;
      const fileNameLower = fileName.toLowerCase();
      const hasPbxExtension = fileNameLower.endsWith('.pbx');

      // 1. Peek at the first byte to identify the marker without loading the whole file
      const headerBlob = file.slice(0, 1);
      const headerBuf = await headerBlob.arrayBuffer();
      const marker = new Uint8Array(headerBuf)[0];

      // 2. Detect and Process Stowaway (Steganography) - ONLY for Images
      // This still requires the full buffer for the stego check logic.
      const isImage = /\.(jpg|jpeg|png)$/.test(fileNameLower);
      if (isImage) {
        try {
          // PASS THE FILE (Blob) directly, not the full buffer
          const found = await checkImageForStowaway(file, fileName);
          if (found) continue;
        } catch (stegoErr) {
          console.error("Stego check failed:", stegoErr);
        }
      }

      // --- IDENTIFY THE MODE ---
      const knownMarkers = [0, 1, 56, 72, 73, 128, 150, 164];
      const isEncrypted = hasPbxExtension && knownMarkers.includes(marker);

      const myEmail = document.getElementById("user-email")?.value.trim() || "";
      const isStandardMode = !window.activePadBin && !window.activeFolderKey;

      // 3. ENHANCED SMART GUARD
      const needsIdentity = [0, 1, 56, 72, 73].includes(marker);

      if (isStandardMode && needsIdentity) {
        if (!masterPwd || masterPwd.length < 1) {
          showStatusMsg("Master Key required to access your keys.", "bad");
          document.getElementById('m-pass').focus();
          return false;
        }
        if (!myEmail) {
          showStatusMsg("Email required for key derivation.", "special");
          document.getElementById("user-email")?.focus();
          return false;
        }
      }

      // --- 4. ROUTE TO PROCESSING ---
      let success = false;

      if (isEncrypted) {
        if (marker === 150) {
          // Certified logic still uses full buffer as it's typically small text
          const fileInBin = new Uint8Array(await file.arrayBuffer());
          success = await processVerification(fileInBin, true);
        } else {
          const outName = hasPbxExtension ? fileName.slice(0, -4) : fileName + '.dec';
          // PASS THE BLOB (file) directly to decryption
          success = await processFileDecryption(file, outName);
        }
      }
      // B. ENCRYPTION PATH: Raw files
      else {
        const state = getEncryptionState();
        let targetMode = 72;

        if (state.mode === 'anon') targetMode = 0;
        if (state.mode === 'pq-anon') targetMode = 1;
        if (state.mode === 'pq-signed') targetMode = 73;
        if (state.mode === 'readonce') targetMode = 56;

        const outName = fileName + '.pbx';
        // PASS THE BLOB (file) directly to encryption
        success = await processFileEncryption(file, outName, targetMode);
      }

      if (!success) return;
    }
  } catch (err) {
    console.error("File processing error:", err);
    showStatusMsg("Error processing files.", "bad");
  }
}

// Helper: Promise-based file reader
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(fr.result);
    fr.onerror = () => {
      console.error("FileReader error:", fr.error); // 👈 LOG ERROR
      reject(fr.error);
    }
    fr.readAsArrayBuffer(file);
  });
}

// Helper: Trigger browser download
function triggerDownload(data, fileName) {
  // If data is already a Blob, use it. Otherwise, wrap the Uint8Array in a Blob.
  const blob = (data instanceof Blob) ? data : new Blob([data], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
}

/**
 * Pings the existing agent first. Only requests re-injection 
 * if the agent is unresponsive.
 */
function requestAgentStatus(tabId) {
  // 1. Try to talk to the agent that is already on the page
  chrome.tabs.sendMessage(tabId, { type: "GET_CURRENT_STATE" }, (response) => {
    if (chrome.runtime.lastError || !response) {
      // 2. ONLY if the agent is missing do we ask the background to inject
      chrome.runtime.sendMessage({
        action: "PANEL_ACTIVE",
        tabId: tabId
      }, handleConnectionResponse);
    } else {
      // 3. Agent is alive! Update UI silently and skip the red error path
      handleConnectionResponse({ success: true, state: response });
    }
  });
}

/**
 * Identifies internal or protected pages where 
 * extension interaction is strictly forbidden.
 */
function isRestrictedUrl(url) {
  if (!url) return true;
  return (
    url.startsWith('chrome://') ||
    url.startsWith('edge://') ||
    url.startsWith('about:') ||
    url.includes('chromewebstore.google.com')
  );
}

async function startPanelLogic(url, tabId) {
  if (isInitialized) return;
  isInitialized = true;

  window.currentTabUrl = url;
  window.currentTabId = tabId;

  requestAgentStatus(tabId);
}

//to display side panel
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'session' && changes.activeTabUrl) {
    startPanelLogic(changes.activeTabUrl.newValue, changes.activeTabId?.newValue);
  }
});

// 1. Create a flag to prevent double-initialization
let isInitialized = false;

// Add to the bottom of sidepanel_UI.js
document.addEventListener('DOMContentLoaded', async () => {
  const data = await chrome.storage.session.get(["activeTabUrl", "activeTabId"]);
  if (data.activeTabId) {
    window.currentTabId = data.activeTabId;

    // 1. BRIDGE THE GAP: Restore the manual lock before updateUI runs
    const key = `tabUI_${window.currentTabId}`;
    const uiData = await chrome.storage.session.get([key]);

    if (uiData[key]) {
      // Populate the volatile object updateUI uses as a 'Manual Lock'
      activeTabsByTabId[window.currentTabId] = uiData[key];
      console.log("[DEBUG] Manual lock restored from session:", uiData[key]);
    }
  }

  if (data.activeTabUrl) {
    startPanelLogic(data.activeTabUrl, data.activeTabId);
  }

  // 1. Load the global directory from storage immediately
  try {
    if (typeof loadLocDir === 'function') {
      await loadLocDir();
    } else {
      // Fallback if crypto-common.js isn't loaded yet or function is missing
      const data = await chrome.storage.sync.get(['locDir']);
      window.locDir = data.locDir || {};
      console.log("Global locDir initialized via fallback.");
    }
  } catch (e) {
    console.error("Failed to initialize directory:", e);
    window.locDir = window.locDir || {}; // Ensure it's at least an empty object
  }

  // 2. Restore the tab AFTER setting window.currentTabId
  if (window.currentTabId) {
    const key = `tabUI_${window.currentTabId}`;
    const uiData = await chrome.storage.session.get([key]);
    if (uiData[key]) {
      // Fill the volatile object so updateUI respects the lock
      activeTabsByTabId[window.currentTabId] = uiData[key];
      switchTab(uiData[key]);
    }
  }

  // 2. Continue with the rest of the setup
  if (typeof startMasterPwdTimeout === 'function') {
    startMasterPwdTimeout();
  }

  initTheme();  //switch to dark or lite according to saved preference
  setupCryptoCardListeners();

  // Update stego capacity when switching between PNG and JPG formats
  document.querySelectorAll('input[name="stego-format"]').forEach(radio => {
    radio.addEventListener('change', () => {
      const preview = document.getElementById('stego-image-preview');
      if (preview && preview.src && preview.style.display !== 'none') {
        const isPng = document.getElementById('stego-format-png').checked;
        if (typeof window.updateStegoCapacity === 'function') {
          window.updateStegoCapacity(preview, isPng);
        }
      }
    });
  });

  if (typeof updateRecipientStatus === 'function') {
    updateRecipientStatus();
  }

  document.getElementById('btn-chat').addEventListener('click', async () => {
    //pro feature
    if (!window.checkProGate()) return;

    const mainBox = document.getElementById('mainBox');
    const lockList = document.getElementById('lockList');

    // 1. Get the host from Chrome Sync (License or Manual inject)
    const storage = await chrome.storage.sync.get(['customJitsiHost']);
    const host = storage.customJitsiHost || "meet.jit.si";

    const userMsg = mainBox.innerText.trim() || "Secure Chat Requested";
    const roomID = "PB-" + Math.random().toString(36).substring(2, 14);

    const passBuffer = new Uint8Array(32);
    crypto.getRandomValues(passBuffer);
    const roomPass = Array.from(passBuffer).map(b => b.toString(16).padStart(2, '0')).join('');

    // 2. Stage with the 'h' field included
    const inviteObj = {
      m: userMsg,
      r: roomID,
      p: roomPass,
      h: host
    };

    mainBox.innerText = "\x07" + JSON.stringify(inviteObj);

    // 3. Standard 'Me' logic
    if (lockList) {
      const selected = Array.from(lockList.selectedOptions).map(o => o.value.trim()).filter(s => s);
      if (selected.length > 0) {
        for (let i = 0; i < lockList.options.length; i++) {
          if (lockList.options[i].value.toLowerCase() === 'me') {
            lockList.options[i].selected = true;
            break;
          }
        }
      }
    }

    startEncryption();
  });

  const closeDirBtn = document.getElementById('close-directory');
  if (closeDirBtn) {
    closeDirBtn.addEventListener('click', () => {
      // Delegate to the DirectoryEditor's close method
      if (typeof DirectoryEditor !== 'undefined' && DirectoryEditor.close) {
        DirectoryEditor.close();
      }
    });
  }

  const mainBox = document.getElementById('mainBox');
  if (mainBox) {
    mainBox.addEventListener('paste', (e) => {
      const pastedText = (e.clipboardData || window.clipboardData).getData('text');

      if (isMessengerNarrative(pastedText)) {
        setTimeout(() => {
          const rawPass = prompt("Messenger Narrative detected. Key (empty for none):", "");
          if (rawPass === null) return;

          const finalSeed = getStretchedSeed(rawPass);

          // 1. This now returns {type: 0/1, data: Uint8Array(32)}
          const recoveryResult = runUnwrapToUint8(pastedText, finalSeed);

          if (recoveryResult) {
            // 2. This function now handles the internal routing based on the type
            handleRecoveredMessengerData(recoveryResult);
          } else {
            showStatusMsg("Extraction failed. Check Key or text integrity.", "bad");
          }
        }, 100);
      }
      // 3. Fallback to existing auto-decrypt logic
      else {
        setTimeout(() => {
          if (document.getElementById('auto-process-check').checked) {
            document.getElementById('do-decrypt-selection')?.click();
          }
        }, 10);
      }
    });
  }

  // Navigation for the sliding ribbon
  const ribbon = document.getElementById('button-ribbon');

  document.getElementById('btn-more').addEventListener('click', () => {
    ribbon.classList.add('show-pro');
  });

  document.getElementById('btn-less').addEventListener('click', () => {
    ribbon.classList.remove('show-pro');
  });

  // === Pad Mode Drop Target ===
  const stegoContainer = document.getElementById('stego-image-container');
  if (stegoContainer) {
    stegoContainer.addEventListener('dragover', (e) => {
      e.preventDefault();
      const imgPreview = document.getElementById('stego-image-preview');
      const isImageLoaded = imgPreview && imgPreview.src && imgPreview.style.display !== 'none';

      if (isImageLoaded) {
        // STEGO MODE: Greenish tint to signify "Embedding"
        stegoContainer.style.backgroundColor = 'rgba(34, 197, 94, 0.1)';
      } else {
        // PAD MODE: Your original blue tint
        stegoContainer.style.backgroundColor = 'rgba(2, 132, 199, 0.1)';
      }
    });

    // Ensure it resets when the mouse leaves or the drop happens
    stegoContainer.addEventListener('dragleave', () => {
      stegoContainer.style.backgroundColor = '';
    });

    stegoContainer.addEventListener('drop', async (e) => {
      stegoContainer.style.backgroundColor = '';

      //pro feature
      if (!window.checkProGate()) return;

      e.preventDefault();
      const files = e.dataTransfer.files;
      if (files && files.length > 0) {
        const file = files[0];
        const imgPreview = document.getElementById('stego-image-preview');

        // CHECK: Is an image currently loaded as a carrier?
        const isImageLoaded = imgPreview && imgPreview.src && imgPreview.style.display !== 'none';

        if (isImageLoaded) {
          // --- MODE: DIRECT STEGO ENCODE ---
          showStatusMsg(`Preparing ${file.name} for embedding...`, "info");

          const arrayBuffer = await readFileAsArrayBuffer(file);
          const fileBytes = new Uint8Array(arrayBuffer);

          // Create the [Len][Name][Data] payload
          const payload = prepareUnifiedPlaintext(fileBytes, file.name);

          // Trigger the encoding flow (passing the direct payload)
          const isPng = document.getElementById('stego-format-png').checked;
          handleStegoEncode(isPng, payload);

        } else {
          // --- MODE: PAD KEY (Original Behavior) ---
//          const arrayBuffer = await readFileAsArrayBuffer(file);
//          window.activePadBin = new Uint8Array(arrayBuffer);
          window.activePadBin = file;

          // UI Feedback
          const indicator = document.getElementById('pad-active-indicator');
          if (indicator) indicator.style.display = 'block';

          showStatusMsg("Pad Mode activated: " + file.name, "special");
          console.log("Pad loaded into window.activePadBin");
        }
      }
    });

    // UI Logic: Decoy Section with class-based toggling
    const dToggle = document.getElementById('hidden-msg-check');
    const dArea = document.getElementById('decoyMessageArea');
    const dInputArea = document.getElementById('decoy-container'); // Ensure this ID matches your HTML
    const dCount = document.getElementById('decoyByteCount');

    if (dToggle && dInputArea) {
      // 1. INITIAL STATE: Sync UI on load
      dInputArea.classList.toggle('hidden', !dToggle.checked);

      // 2. CHANGE LISTENER
      dToggle.addEventListener('change', () => {
        // Pro gate check
        if (typeof window.checkProGate === 'function' && !window.checkProGate()) {
          dToggle.checked = false;
          return;
        }

        const isVisible = dToggle.checked;

        // Use classList so the CSS 'ghost bar' fix actually triggers
        dInputArea.classList.toggle('hidden', !isVisible);

        if (isVisible && dArea) {
          dArea.focus();
        }
      });
    }

    dArea.addEventListener('input', () => {
      const bytes = encoder.encode(dArea.value).length;
      dCount.textContent = bytes;
      dCount.style.color = bytes > 75 ? 'red' : '#666';
    });
  }

  // 1. SELECTORS
  const modeSelect = document.getElementById('mode-select');
  const hiddenCheck = document.getElementById('hidden-msg-check');
  const lockCheck = document.getElementById('add-lock-check');
  const autoCheck = document.getElementById('auto-process-check');

  // 2. STATE HELPER (Scoped to the UI)
  // This allows other functions to simply call getEncryptionState()
  /**
  * Refined hierarchy: Respects 'certified' regardless of recipients, 
  * but defaults to 'symmetric' for other encryption modes if no recipients are selected.
  */
  window.getEncryptionState = () => {
    const recipients = Array.from(document.getElementById('lockList')?.selectedOptions || [])
      .map(o => o.value.trim()).filter(s => s);

    // Primary ID from your code is 'mode-select'
    const uiMode = document.getElementById('mode-select')?.value;

    let effectiveString;

    // 1. HARD OVERRIDES (External State)
    if (window.activePadBin) {
      effectiveString = 'pad';
    } else if (window.activeFolderKey) {
      effectiveString = 'folder';
    }
    // 2. PROTOCOL OVERRIDE (Certified is a signature, not recipient-encryption)
    else if (uiMode === 'certified') {
      effectiveString = 'certified';
    }
    // 3. ENCRYPTION FALLBACK (If no recipients, it must be Symmetric)
    else if (recipients.length === 0) {
      effectiveString = 'symmetric';
    }
    // 4. STANDARD IDENTITY MODES (Signed, PQ-Signed, Anon, Read-Once)
    else {
      effectiveString = uiMode;
    }

    return {
      mode: effectiveString,
      // Using unified IDs from sidepanel_encrypt.js
      addLock: document.getElementById('add-lock-check')?.checked,
      useHidden: document.getElementById('hidden-msg-check')?.checked,
      auto: document.getElementById('autoCheck')?.checked,
      recipients: recipients
    };
  };

  // 3. REACTIVE UI LOGIC
  // Handle mode-specific UI changes here
  modeSelect.addEventListener('change', () => {
    const state = window.getEncryptionState();

    // Example: Visual feedback when switching modes
    if (state.mode === 'certified') {
      console.log("Narrative mode active: Ensure a Master Key is set.");
    }

    // Ensure Hidden is enabled for certified, Read-once, and Pad
    // (Since you noted they all support it, we keep it active)
    hiddenCheck.disabled = false;
    hiddenCheck.parentElement.style.opacity = "1";
  });

  // 4. ATTACH BUTTON LISTENERS
  // Now that the state helper is ready, buttons can use it
  const encryptBtn = document.getElementById('btn-encrypt-main');
  if (encryptBtn) {
    encryptBtn.addEventListener('click', handleMainAction);
  }

  // Connect Site Button Handler
  document.getElementById('connect-btn')?.addEventListener('click', async () => {
    // 1. In a popup, the active tab is usually the one the popup is attached to.
    // Query without 'url' filters first to see if the permission exists.
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id) {
      showStatusMsg("Could not identify the active tab.", "bad");
      return;
    }

    // 2. DIAGNOSTIC: If URL is missing, activeTab didn't fire.
    let targetUrl = tab.url;

    if (!targetUrl) {
      // If activeTab is granted, we can use tabs.get to see if it populates
      try {
        const fullTab = await chrome.tabs.get(tab.id);
        targetUrl = fullTab.url;
      } catch (e) {
        console.error("Diagnostic - Permission Block:", e.message);
      }
    }

    if (!targetUrl) {
      showStatusMsg("Permission denied. Please refresh the page.", "special");
      return;
    }

    // 3. PROCEED TO PERMANENT CONNECTION
    let origin;
    try {
      origin = new URL(targetUrl).origin + "/*";
    } catch (e) {
      showStatusMsg("Invalid site URL.", "bad");
      return;
    }

    chrome.permissions.request({ origins: [origin] }, (granted) => {
      if (granted) {
        showStatusMsg("Site connected!", "good");
        document.getElementById('connect-btn')?.classList.add('hidden');
        chrome.runtime.sendMessage({ action: "PANEL_ACTIVE", tabId: tab.id });
      } else {
        showStatusMsg("Connection denied.", "bad");
      }
    });
  });

  const upBtn = document.getElementById('scale-up-btn');
  const downBtn = document.getElementById('scale-down-btn');

  if (upBtn) upBtn.addEventListener('click', () => adjustUIScale(1));
  if (downBtn) downBtn.addEventListener('click', () => adjustUIScale(-1));

  // Restore preferred UI scale from storage
  chrome.storage.sync.get(['uiScale'], (data) => {
    if (data.uiScale) {
      document.documentElement.style.setProperty('--root-size', `${data.uiScale}px`);
    }
  });
});

document.getElementById('help-btn')?.addEventListener('click', () => {
  // 1. Identify which tab is currently active in the Side Panel
  const activeTab = document.querySelector('#tab-navigation .tab-btn.active')?.dataset.tab || 'crypto';

  // 2. Map UI tabs to help file suffixes
  const helpMap = { synth: 'passwords', crypto: 'crypto', notes: 'notes' };
  const helpFileName = `help/help_${helpMap[activeTab] || 'crypto'}.html`;

  // 3. Generate the full chrome-extension:// URL
  const helpUrl = chrome.runtime.getURL(helpFileName);

  // 4. Open in a new tab without needing "tabs" permission
  window.open(helpUrl, '_blank');
});

document.getElementById('clear-folder-key')?.addEventListener('click', () => {
  window.activeFolderKey = null;
  document.getElementById('folder-active-indicator').style.display = 'none';
  updateFolderKeyUI();
  showStatusMsg("Folder Key cleared. Standard modes restored.", "info");

  // Optional: Reset the border if you changed it
  document.getElementById('card-crypto').style.borderColor = '';
});

document.getElementById('clear-pad-key')?.addEventListener('click', () => {
  window.activePadBin = null;
  document.getElementById('pad-active-indicator').style.display = 'none';
  showStatusMsg("Pad Mode cleared. Standard modes restored.", "info");
});

// Listen for close event
window.addEventListener("closeDirectory", () => {
  // Ensure directory card is hidden (redundant but safe)
  const dirCard = document.getElementById('directory-card');
  if (dirCard) dirCard.classList.add('hidden');

  // FIX: Access the global window property to avoid ReferenceError
  if (window.isManualForThisTab) {
    const cryptoCard = document.getElementById('card-crypto');
    if (cryptoCard) {
      cryptoCard.classList.remove('hidden');
      // Re-run updateUI to ensure all elements are in the right state
      setTimeout(() => updateUI(lastState), 0);
    }
  } else {
    // Normal state restoration
    updateUI(lastState);
  }
});

// Encryption event Listeners
document.getElementById('encryptBtn').addEventListener('click', startEncryption);

document.getElementById('encryptToFileBtn').addEventListener('click', encryptToFile);

document.getElementById("do-decrypt-selection").addEventListener("click", doDecryptSelection);

document.getElementById("save-sender-lock").addEventListener("click", saveSenderLock);

document.getElementById("ignore-sender-lock").addEventListener("click", () => {
  document.getElementById("sender-prompt-overlay").classList.add("hidden");
  pendingLock = null;
});

// Save email when changed inline to host.crypt
document.getElementById("user-email").addEventListener("change", (e) => {
  const email = e.target.value.trim();
  if (email.includes("@") && currentHost) {
    chrome.storage.sync.get([currentHost], (result) => {
      const hostData = result[currentHost] || {};
      hostData.crypt = hostData.crypt || {};
      hostData.crypt.email = email;
      chrome.storage.sync.set({ [currentHost]: hostData }, () => {
        // setStatus("Email updated for this host");
        showStatusMsg("Email updated for this host", "info");
      });
    });
  }
});

document.getElementById('copyCompose')?.addEventListener('click', async () => {
  const mainBox = document.getElementById('mainBox');
  // Wrap the HTML in a small, monospaced style for a cleaner look in emails
  const styledHtml = `<span style="font-size: 9pt; line-height: 1.2; font-family: monospace;">${mainBox.innerHTML}</span>`;
  const text = mainBox.innerText;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab || !tab.url || tab.url.startsWith('chrome://')) {
    await copyAndScheduleClear(text);
    return;
  }

  chrome.tabs.sendMessage(tab.id, {
    type: "INSERT_ENCRYPTED_TEXT",
    text: "\n" + styledHtml + "\n"
  }, async (response) => {
    if (chrome.runtime.lastError || !response || !response.success) {
      await copyAndScheduleClear(text);
    } else {
      showStatusMsg("Injected directly.", "good");
      mainBox.innerHTML = "";
    }
  });
});

document.getElementById('clearCompose')?.addEventListener('click', () => {
  const box = document.getElementById('mainBox');
  box.innerHTML = '';
  box.focus();
});

// Event Listener for decoy decrypt button
document.getElementById('decoyDecryptBtn').addEventListener('click', doDecoyDecrypt);

// Update listeners for notes card
document.getElementById("save-notes-btn").onclick = () => saveNote("notes");
document.getElementById("save-once-btn").onclick = () => saveNote("once");

document.getElementById("clear-notes-btn").addEventListener("click", clearNotes);

document.getElementById("unlock-notes-btn").addEventListener("click", unlockNotes);

document.getElementById('safe-view-btn').addEventListener('click', () => {
  //pro feature
  if (!window.checkProGate()) return;

  // 1. Request the origins (this is the "User Gesture" Chrome requires)
  // If already granted, this returns true instantly with NO popup.
  const originRequest = {
    origins: ["https://*/*", "http://*/*"]
  };

  chrome.permissions.request(originRequest, (granted) => {
    if (chrome.runtime.lastError) {
      console.error("Permission Error:", chrome.runtime.lastError.message);
    }

    if (!granted) {
      showStatusMsg("Safe Space limited: permission denied.", "bad");
    }

    // 2. Now proceed to open the Safe Space
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:')) {
        showStatusMsg("Cannot isolate this page type", "bad");
        return;
      }

      const safeViewUrl = chrome.runtime.getURL(`safeview.html?url=${encodeURIComponent(tab.url)}`);
      chrome.tabs.create({ url: safeViewUrl });

      showStatusMsg("Opening Safe Space...", "special");
    });
  });
});

document.getElementById('btn-split').addEventListener('click', splitJoin);

/**
 * Manages the "Wrap" button visibility and logic in the Status Area.
 * Call this inside updateUI() to keep it in sync with the app state.
 */
// Global listener for the Wrap link
document.addEventListener('click', (e) => {
  if (e.target && e.target.id === 'messenger-wrap-key') {
    console.log("Global Catch: Wrap link detected!");
    handleWrapLogic();
  }
});

async function handleWrapLogic() {
  const rawPass = prompt("Camo Key (leave empty for none):", "");
  if (rawPass === null) return;

  // Apply wiseHash stretching if a Key exists
  const finalSeed = getStretchedSeed(rawPass);

  let bytes = window.activeFolderKey;
  if (!bytes) return showStatusMsg("No active key found.", "bad");

  // Type safety check
  if (!(bytes instanceof Uint8Array)) {
    if (typeof bytes === 'string') {
      bytes = new Uint8Array(bytes.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    } else {
      bytes = new Uint8Array(bytes);
    }
  }

  try {
    const html = wrapToMessengerHTML(bytes, finalSeed, "folder");
    const mainBox = document.getElementById('mainBox');
    if (mainBox) {
      mainBox.innerHTML = html;
      showStatusMsg("Key wrapped into narrative.", "good");
    }
  } catch (err) {
    console.error("Wrap Error:", err);
  }
}

function updateFolderKeyUI() {
  const folderIndicator = document.getElementById('folder-active-indicator');
  if (!folderIndicator) return;

  if (window.activeFolderKey) {
    folderIndicator.style.display = 'block';
  } else {
    folderIndicator.style.display = 'none';
  }
}

/**
 * Single source of truth for the UI state.
 * Maps the new dropdown and existing checkboxes.
 */
window.getEncryptionState = () => {
  return {
    mode: document.getElementById('mode-select')?.value || 'signed',
    addLock: document.getElementById('add-lock-check')?.checked || false,
    useHidden: document.getElementById('hidden-msg-check')?.checked || false,
    auto: document.getElementById('auto-process-check')?.checked || false
  };
};

//for notes card: capture sanitized HTML from the active tab, clean it with DOMPurify, and insert into the notes textarea
document.getElementById('capture-download-btn').addEventListener('click', async () => {
  //pro feature
  if (!window.checkProGate()) return;

  const btn = document.getElementById('capture-download-btn');
  const originalText = "Open Sanitized Page";

  btn.innerText = "Capturing...";
  btn.disabled = true;

  // 1. Initialize the Panopticon Tally
  let panopticonStats = { images: 0, scripts: 0, active: 0 };

  // 2. The Enhanced "Privacy Hook"
  DOMPurify.addHook('beforeSanitizeElements', (node) => {
    // Track & Replace Images
    if (node.tagName === 'IMG') {
      panopticonStats.images++;
      const altText = node.getAttribute('alt') || 'Image';
      const placeholder = document.createElement('span');
      placeholder.innerText = `[${altText}]`;
      placeholder.style.cssText = "font-size: 11px; color: #ff5722; border: 1px dashed #ff5722; padding: 2px 4px; border-radius: 3px; cursor: pointer; vertical-align: middle; margin: 0 2px;";
      node.parentNode.insertBefore(placeholder, node);
    }

    // Track Scripts
    if (['SCRIPT', 'NOSCRIPT'].includes(node.tagName)) {
      panopticonStats.scripts++;
    }

    // Track Active/Dangerous Elements
    const activeTags = ['IFRAME', 'FORM', 'OBJECT', 'EMBED', 'INPUT', 'BUTTON'];
    if (activeTags.includes(node.tagName)) {
      panopticonStats.active++;
    }
  });

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    const response = await new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(tab.id, { action: "get_sanitized_source" }, (res) => {
        if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
        else resolve(res);
      });
    });

    if (!response) throw new Error("No content received");

    // 3. Purify the HTML (Triggers the Hook)
    const cleanBody = DOMPurify.sanitize(response.body || response.html, {
      FORBID_TAGS: ['script', 'iframe', 'form', 'object', 'embed', 'input', 'button', 'img'],
      FORBID_ATTR: ['on*'],
      ADD_ATTR: ['class', 'style', 'href'],
      KEEP_CONTENT: true
    });

    // Generate the summary message
    const tallyMsg = `Blocked: ${panopticonStats.images} images, ${panopticonStats.scripts} scripts, and ${panopticonStats.active} active elements.`;

    const finalDoc = `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8">
    <title>Sanitized: ${response.title || 'Page'}</title>
    <style>
      ${response.css || ''} 
      body { padding-top: 60px; } /* Space for the sticky banner */
      .pb-banner { 
        background: #ff5722; color: white; padding: 10px; 
        text-align: center; font-family: sans-serif;
        position: fixed; top: 0; left: 0; right: 0; z-index: 99999; 
        border-bottom: 2px solid #e64a19; box-shadow: 0 2px 5px rgba(0,0,0,0.2);
      }
      .pb-title { font-weight: bold; display: block; margin-bottom: 3px; }
      .pb-stats { font-size: 12px; opacity: 0.9; }
      span[style*="dashed"] { vertical-align: middle; }
    </style>
  </head>
  <body>
    <div class="pb-banner">
      <span class="pb-title">Privacy Bar: Sanitized View</span>
      <span class="pb-stats">${tallyMsg}</span>
    </div>
    <div style="position: relative; padding: 20px;">
      ${cleanBody}
    </div>
  </body>
  </html>`;

    const blob = new Blob([finalDoc], { type: 'text/html' });
    chrome.tabs.create({ url: URL.createObjectURL(blob) });

    btn.innerText = "Success!";
  } catch (err) {
    console.error("Sanitization failed:", err);
    btn.innerText = "Error";
  } finally {
    // 4. Cleanup Hook and Reset UI
    DOMPurify.removeHook('beforeSanitizeElements');
    setTimeout(() => {
      btn.innerText = originalText;
      btn.disabled = false;
    }, 2000);
  }
});

/**
 * Copies text to clipboard and schedules an auto-clear.
 * @param {string} text - The sensitive data to copy.
 * @param {number} delayMs - Time in milliseconds before clearing (default 60,000).
 */
// 1. The Global Flag
let localWipeFlag = false;

/**
 * The Unified Copy Function
 */
async function copyAndScheduleClear(text, delayMs = 60000) {
  try {
    // Perform the copy (Always works on click)
    await navigator.clipboard.writeText(text);
    showStatusMsg("Copied! Security wipe armed (60s).", "info");

    // Start the local timer
    setTimeout(() => {
      localWipeFlag = true;
      console.log("Privacy Bar: Clipboard wipe is now primed.");
    }, delayMs);

  } catch (err) {
    console.error("Copy failed:", err);
  }
}

/**
 * The "Lazy Reaper" Listener
 * This catches ANY click on the UI and nukes the clipboard if the flag is true.
 */
document.body.addEventListener('click', async () => {
  if (localWipeFlag) {
    try {
      await navigator.clipboard.writeText(""); // Nukes the clipboard
      localWipeFlag = false; // Reset the flag
      showStatusMsg("Security: Clipboard wiped.", "info");
      console.log("Privacy Bar: User gesture used to wipe clipboard.");
    } catch (err) {
      // If it fails (e.g. window lost focus), the flag stays true for the next click
      console.error("Manual wipe failed:", err);
    }
  }
}, true);

// --- NEW LISTENER FOR THE 'CREATE INVITATION' LINK ---
document.getElementById('create-invitation-btn').addEventListener('click', async () => {
  const mp = document.getElementById('m-pass')?.value.trim();
  if (!mp) { showStatusMsg("Master Key required.", "bad"); return; }

  const storage = await chrome.storage.sync.get([currentHost]);
  const myEmail = storage[currentHost]?.crypt?.email || "";
  const common = await prepareCommonData(mp, myEmail);

  if (common) {
    await finalizeAndInject({
      finalBin: new Uint8Array(0),
      modeLabel: "INVITATION",
      base36Lock: common.base36Lock,
      addLock: true
    });
  }
});

//for the Activate Pro button
document.getElementById('manual-activate-btn')?.addEventListener('click', () => {
  // Trigger the same modal that pops for locked features
  if (typeof window.showUpgradeModal === 'function') {
    window.showUpgradeModal();
  } else {
    // Fallback: search for your specific license-gating trigger
    const proActionMessage = "Please enter your license key to unlock Pro features.";
    console.warn("Privacy Bar: Manual activation triggered.");
  }
});

//for the report bug link
document.getElementById('report-bug-link')?.addEventListener('click', async (e) => {
  e.preventDefault();

  const version = chrome.runtime.getManifest().version;
  const reportUrl = `https://privacybar.net/report.html?v=${version}`;

  // Minimalist Diagnostic Bundle
  const status = window.PB_PRO_STATUS || { active: false };
  // Helper to get a clean OS name
  const getOS = () => {
    const ua = navigator.userAgent;
    if (ua.indexOf("Win") !== -1) return "Windows";
    if (ua.indexOf("Mac") !== -1) return "MacOS";
    if (ua.indexOf("Linux") !== -1) return "Linux";
    return "Unknown OS";
  };

  // Helper to get just the Chrome version
  const getChromeVersion = () => {
    const raw = navigator.userAgent.match(/Chrome\/([0-9.]+)/);
    return raw ? raw[1] : "Unknown";
  };

  const debugData = {
    v: version,
    pro: status.active,
    os: getOS(),
    chrome: getChromeVersion(),
    ts: new Date().toISOString()
  };

  try {
    // Copy to clipboard for the user to paste into the form
    await navigator.clipboard.writeText(JSON.stringify(debugData, null, 2));
    alert("Diagnostics copied. Redirecting to report vault...");
  } catch (err) {
    console.error("Clipboard blocked.", err);
  }

  window.open(reportUrl, '_blank');
});

// Trigger injection for the current tab immediately on side panel load
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const id = tabs[0]?.id;
  if (id) {
    // If we haven't remembered a tab for this ID yet, default to 'synth'
    const initialTab = activeTabsByTabId[id] || 'notes';

    // This call now handles: 
    // 1. UI Visibility 
    // 2. Button Highlighting 
    // 3. Sending the PANEL_ACTIVE message to background.js
    switchTab(initialTab);
  }
});

window.addEventListener('unload', () => {
  chrome.runtime.sendMessage({ action: "PANEL_CLOSED" });
});

/**
 * THEME: Initialize based on Storage -> System Preference
 */
async function initTheme() {
  const data = await chrome.storage.sync.get(['ui_theme']);
  let theme = data.ui_theme;

  // Day Zero: If no saved preference, match the browser
  if (!theme) {
    const isSystemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    theme = isSystemDark ? 'dark' : 'light';
  }

  applyTheme(theme);

  // Wire the button
  const btn = document.getElementById('theme-btn');
  if (btn) btn.addEventListener('click', toggleTheme);
}

/**
 * THEME: Toggle and Save to Sync
 */
async function toggleTheme() {
  const isLight = document.documentElement.classList.toggle('light-mode');
  const newTheme = isLight ? 'light' : 'dark';

  applyTheme(newTheme);
  await chrome.storage.sync.set({ 'ui_theme': newTheme });
}

/**
 * THEME: Apply Visual State
 */
function applyTheme(theme) {
  const btn = document.getElementById('theme-btn');
  if (theme === 'light') {
    document.documentElement.classList.add('light-mode');
    if (btn) btn.textContent = 'DARK';
  } else {
    document.documentElement.classList.remove('light-mode');
    if (btn) btn.textContent = 'LITE';
  }

  // Ensure the folder key UI also respects the new theme colors
  if (typeof updateFolderKeyUI === 'function') updateFolderKeyUI();
}

/**
 * ### NEW FUNCTION: adjustUIScale
 * Manually scales the UI by adjusting the CSS variable.
 * Persists to storage so the scale sticks across sessions.
 */
async function adjustUIScale(delta) {
  const data = await chrome.storage.sync.get(['uiScale']);
  let currentScale = data.uiScale || 15; 

  // Clamp between 12px and 22px to prevent UI breakage
  currentScale = Math.min(Math.max(currentScale + delta, 12), 22);

  document.documentElement.style.setProperty('--root-size', `${currentScale}px`);
  await chrome.storage.sync.set({ uiScale: currentScale });
  
  if (typeof showStatusMsg === 'function') {
    showStatusMsg(`Scale: ${currentScale}px`, "info");
  }
}