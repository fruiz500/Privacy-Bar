/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

// --- Global locDir Management ---

// 1. The global directory object
var locDir = {}; // Using var to ensure it's truly global

// 2. Helper to persist the directory
async function syncLocDir(directoryToSave) {
  // If no directory is passed, use the current window.locDir as a fallback.
  // If BOTH are missing, stop immediately to prevent a wipe [cite: 2026-04-21].
  const dataToSave = directoryToSave || window.locDir;

  if (!dataToSave) {
    console.error("syncLocDir: Aborted to prevent clearing storage with undefined data.");
    return;
  }
  // 1. Update the Global Memory first
  // This ensures window.locDir and the local variable stay identical
  window.locDir = dataToSave;

  return new Promise((resolve, reject) => {
    // 2. Save the passed object to the 'locDir' key in Sync
    chrome.storage.sync.set({ locDir: dataToSave }, () => {
      if (chrome.runtime.lastError) {
        console.error("Error syncing locDir:", chrome.runtime.lastError);
        reject(chrome.runtime.lastError);
      } else {
        console.log("Global locDir synced to storage and memory.");

        // 3. Trigger UI Update
        if (typeof updateLockList === 'function') {
          updateLockList();
        }

        resolve();
      }
    });
  });
}

/**
 * Loads the locDir from chrome.storage.sync into the global variable.
 * Call this once during app initialization.
 */
async function loadLocDir() {
  return new Promise((resolve, reject) => {
    chrome.storage.sync.get(['locDir'], (result) => {
      if (chrome.runtime.lastError) {
        console.error("Error loading locDir:", chrome.runtime.lastError);
        reject(chrome.runtime.lastError);
      } else {
        // Assign to the shared variable
        locDir = result.locDir || {};
        console.log("Global locDir loaded from storage.");

        // Ensure the UI reflects the loaded directory immediately
        if (typeof updateLockList === 'function') {
          updateLockList(locDir);
        }

        resolve(locDir);
      }
    });
  });
}

async function resetReadOnce(recipient) {
  const reply = confirm('Do you really want to reset the current Read-Once exchange with ' + recipient + '? This cannot be undone.');
  if(!reply) return;
  
  // 1. Update the in-memory global state first [cite: 2026-03-28]
  if (window.locDir && window.locDir[recipient]) {
    delete window.locDir[recipient].ro;
    console.log(`Deleted 'ro' key for ${recipient} in memory.`);
  } else {
    console.error(`Recipient '${recipient}' not found.`);
    return; // Stop if there's nothing to reset
  }

  // 2. Use our existing helper to persist and WAIT for completion [cite: 2026-04-21]
  try {
    await syncLocDir(window.locDir);
    console.log("locDir successfully updated in sync storage.");
  } catch (err) {
    console.error("Failed to sync reset state:", err);
  }
}

// 3. Explicitly make them global (good practice)
window.locDir = locDir;
window.syncLocDir = syncLocDir;
window.loadLocDir = loadLocDir;
window.resetReadOnce = resetReadOnce;

//code for editing the directory entries (synth and locDir) in sync storage

let currentMode = "synth";        //initial mode (can be 'synth' or 'locDir')
let currentHost = "";
let masterPasswordContext = null; // 'synth', 'decrypt', or 'notes'

function setHost(host) {
  currentHost = host;
}

function setMode(mode) {
  currentMode = mode;
  updateInputLabels();
}

// Update input placeholders based on mode

function updateInputLabels() {
  const nameInput = document.getElementById("new-lock-name");
  const valueInput = document.getElementById("new-lock-value");
  if (!nameInput || !valueInput) return;

  if (currentMode === "synth") {
    nameInput.placeholder = "Name (e.g. Alice)";
    valueInput.placeholder = "Lock (Public Key)";
  } else {
    nameInput.placeholder = "Name/Email";
    valueInput.placeholder = "Value";
  }
}

// Render Directory Entries (Exclusively for locDir)
let lastRenderTime = 0;

async function renderDirectory() {
  const now = Date.now();

  if (now - lastRenderTime < 500) {
    console.warn("Render: Blocked by debounce.");
    return;
  }
  lastRenderTime = now;

  const container = document.getElementById("directory-list");
  if (!container) {
    console.error("Render: Container #directory-list not found!");
    return;
  }

  container.innerHTML = '<div style="padding: 10px; text-align: center;">Loading...</div>';
  updateInputLabels();

  // 1. Load Global Directory
  const globalData = await chrome.storage.sync.get(["locDir"]);
  let directory = globalData.locDir || {};

  // 2. Include "(Me)" entry from site-specific crypt data
  if (currentHost) {
    const hostData = await chrome.storage.sync.get([currentHost]);
    const crypt = (hostData[currentHost] || {}).crypt;
    if (crypt && crypt.email) {
      // Create a structured object for (Me) to match locDir format
      directory["(Me) " + crypt.email] = {
        lock: crypt.lock || "No Lock",
        pqlock: crypt.pqlock || null
      };
    }
  }

  // 3. Clear and Render
  container.innerHTML = "";
  const entries = Object.entries(directory).filter(([name]) => name && name !== "null");

  if (entries.length === 0) {
    container.innerHTML = '<div style="padding: 10px; color: #666;">No entries found.</div>';
    return;
  }

  entries.forEach(([name, value]) => {
    const item = document.createElement("div");
    const isMe = name.startsWith("(Me) ");

    // Normalize data: Identify if we have a PQ lock without storing it in the DOM
    const isObj = (typeof value === 'object' && value !== null);
    const lock36 = isObj ? value.lock : value;
    const hasPQ = isObj && !!value.pqlock;

    // Generate the 14-char Fingerprint (using the string in memory)
    const hashili = makePQPrint(isObj ? value.pqlock : null);

    item.style = "display: flex; justify-content: space-between; align-items: center; padding: 8px; border-bottom: 1px solid #eee; font-size: 12px;"
      + (isMe ? " background: #f0f9ff; border-left: 3px solid #0369a1;" : "");

    // CRITICAL: We only pass the NAME in data-name. 
    // We do NOT stringify the 'value' object into the HTML attributes.
    const actionButtons = isMe
      ? `<button class="copy-lock-entry" data-name="${name}" style="padding: 2px 5px; cursor: pointer;">Copy</button>
         <button class="wrap-lock-entry" data-value="${lock36}" style="padding: 2px 5px; cursor: pointer;">Wrap</button>`
      : `<button class="edit-entry" data-name="${name}" style="padding: 2px 5px; cursor: pointer;">Edit</button>
         <button class="delete-entry" data-name="${name}" style="padding: 2px 5px; cursor: pointer; color: red;">Del</button>`;

    item.innerHTML = `
      <div style="flex: 1; min-width: 0; overflow: hidden; margin-right: 10px;">
        <div style="display: flex; align-items: baseline; gap: 6px;">
          <strong style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${name}</strong>
          <span style="color: #0369a1; font-weight: bold; font-family: monospace; font-size: 10px; flex-shrink: 0;">[${hashili}]</span>
        </div>
        <div style="color: #666; font-family: monospace; font-size: 10px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
          ${lock36}
        </div>
      </div>
      <div style="display: flex; gap: 5px; flex-shrink: 0; align-items: center;">
        ${actionButtons}
        ${(isObj && value.ro) ? `<button class="reset-ro-entry" data-name="${name}" title="Reset Read-once" style="padding: 2px 4px; cursor: pointer; color: #007bff; font-size: 10px; width: 55px; flex-shrink: 0;">Reset RO</button>` : ''}
      </div>
    `;

    container.appendChild(item);
  });

  // 4. Delete Logic (No changes needed)
  container.querySelectorAll(".delete-entry").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const name = e.target.dataset.name;
      if (!confirm(`Remove ${name} from directory?`)) return;
      if (name.startsWith("(Me) ")) {
        const d = await chrome.storage.sync.get([currentHost]);
        if (d[currentHost]?.crypt) {
          delete d[currentHost].crypt;
          await chrome.storage.sync.set({ [currentHost]: d[currentHost] });
        }
      } else {
        const d = await chrome.storage.sync.get(["locDir"]);
        let locDir = d.locDir || {};
        delete locDir[name];
        await syncLocDir(locDir);
      }
      renderDirectory();
    });
  });

  // 5. Edit Logic (Enhanced for PQ/Hybrid input)
  container.querySelectorAll(".edit-entry").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const name = e.currentTarget.dataset.name;
      const entry = directory[name];

      // --- PREPARE DISPLAY DATA (Storage Unpadded Base64) ---
      let currentClassic = (typeof entry === 'object' && entry !== null) ? (entry.lock || "") : (entry || "");
      let currentPQBase64 = (typeof entry === 'object' && entry !== null) ? (entry.pqlock || null) : null;

      let displayValue = currentClassic;

      if (currentPQBase64) {
        try {
          // 1. Convert Latin-1 to Base64
          // 2. Strip padding (= characters) from the end
          const pqBase64Unpadded = btoa(currentPQBase64).replace(/=+$/, '');

          displayValue = currentClassic ? `${currentClassic}//////${pqBase64Unpadded}` : pqBase64Unpadded;
        } catch (err) {
          console.error("Edit: Display encoding failed.", err);
        }
      }

      // 1. Show the prompt
      let input = prompt(`Update Identity for ${name} (Classic, PQ, or Bundle):`, displayValue);
      if (input === null || input.trim() === "") return;
      input = input.trim();

      // 2. Intelligent Parser Logic (UI Base64 -> Storage)
      let newClassicLock = null;
      let newPQLockBase64 = null;
      const classicRegex = /^[0-9a-kLm-z]{50}/;

      if (input.includes("//////")) {
        const parts = input.split("//////");
        const potentialClassic = parts[0].trim();
        const potentialPQB64 = parts[1].trim();

        if (classicRegex.test(potentialClassic)) {
          newClassicLock = potentialClassic;
        }

        try {
          // decodeBase64 should handle unpadded strings
          const pqBytes = decodeBase64(potentialPQB64);
          if (pqBytes.length === 1184) newPQLockBase64 = encodeBase64(pqBytes);
        } catch (err) { console.error("Edit: PQ part decode failed."); }

      } else {
        // Fallback for standalone inputs
        if (input.length >= 50 && classicRegex.test(input.substring(0, 50))) {
          newClassicLock = input.substring(0, 50);
          if (input.length > 56) {
            // Try to catch unpadded PQ after the classic lock
            const pqPart = input.substring(56).trim();
            try {
              const pqBytes = decodeBase64(pqPart);
              if (pqBytes.length === 1184) newPQLockBase64 = encodeBase64(pqBytes);
            } catch (err) { }
          }
        } else if (input.length > 80) { // PQ locks are quite long even without padding
          try {
            const pqBytes = decodeBase64(input);
            if (pqBytes.length === 1184) newPQLockBase64 = encodeBase64(pqBytes);
          } catch (err) { }
        } else {
          newClassicLock = input;
        }
      }

      // 3. Update the storage
      const d = await chrome.storage.sync.get(["locDir"]);
      let locDir = d.locDir || {};
      const existing = locDir[name] || {};

      locDir[name] = {
        lock: newClassicLock || existing.lock || "No Lock",
        pqlock: newPQLockBase64 || existing.pqlock || null,
        ro: existing.ro || null
      };

      await syncLocDir(locDir);
      renderDirectory();
      showStatusMsg(`Updated ${name}`, "good");
    });
  });

  // 6. Reset Read-once Logic (No changes needed)
  container.querySelectorAll(".reset-ro-entry").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      // Use currentTarget to ensure we always get the button's dataset
      const name = e.currentTarget.dataset.name;
      if (!name) return;

      // 1. Wait for the state to be cleared in storage
      await resetReadOnce(name);

      // 2. Re-render the whole card. 
      renderDirectory();
    });
  });

  // 7. Copy "Me" Lock Logic (Bundles PQ + Classic)
  container.querySelectorAll(".copy-lock-entry").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const name = e.target.dataset.name;
      const d = await chrome.storage.sync.get([currentHost]);
      const crypt = d[currentHost]?.crypt;
      if (crypt) {
        // Bundle the keys: ClassicLock//////pqlock
        const bundle = crypt.pqlock ? `${crypt.lock}//////${crypt.pqlock}` : crypt.lock;
        copyAndScheduleClear(bundle);
        showStatusMsg("Identity bundle copied!", "good");
      }
    });
  });

  // 8. Wrap Logic (No changes needed)
  container.querySelectorAll(".wrap-lock-entry").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const lockB36 = e.target.dataset.value;
      const rawPass = prompt("Camo Password (optional):", "");
      if (rawPass === null) return;
      const finalSeed = getStretchedSeed(rawPass);
      const lockBytes = decodeBase36ToUint8(lockB36);
      const html = wrapToMessengerHTML(lockBytes, finalSeed, "lock");
      document.getElementById('mainBox').innerHTML = html;
      window.DirectoryEditor.close();
      showStatusMsg("Lock wrapped into narrative.", "good");
    });
  });
}

// Add Entry Logic
document.getElementById("add-to-directory").addEventListener("click", async () => {
  const name = document.getElementById("new-lock-name").value.trim();
  const value = document.getElementById("new-lock-value").value.trim();
  if (!name || !value) return;

  if (currentMode === "synth") {
    const data = await chrome.storage.sync.get([currentHost]);
    const hostData = data[currentHost] || {};
    hostData.synth = hostData.synth || {};
    hostData.synth[name] = value;
    await chrome.storage.sync.set({ [currentHost]: hostData });
  } else {
    const data = await chrome.storage.sync.get(["locDir"]);
    const locDir = data.locDir || {};

    const isPro = window.PB_PRO_STATUS && window.PB_PRO_STATUS.active;
    if (!isPro && Object.keys(locDir).length >= 10 && !locDir[name]) {
      if (typeof window.checkProGate === 'function') window.checkProGate();
      return;
    }

    let classicLock = null;
    let pqLockBase64 = null;

    const classicRegex = /^[0-9a-kLm-z]{50}/;

    // 1. Segmented Format Check (ID + ////// + Lock)
    if (value.length >= 50 && classicRegex.test(value)) {
      classicLock = value.substring(0, 50);

      if (value.length > 56) {
        const pqPart = value.substring(56).trim();
        try {
          const pqBytes = decodeBase64(pqPart);
          // Standard PB (1184) or KyberLock (2496)
          if (pqBytes.length === 1184) {
            pqLockBase64 = encodeBase64(pqBytes);
          } else if (pqBytes.length === 2496) {
            // KL Detected: Extract ML-KEM portion [0-1184]
            pqLockBase64 = encodeBase64(pqBytes.slice(0, 1184));
          }
        } catch (e) { console.error("PQ extraction failed."); }
      }
    }
    // 2. Standalone Lock Check
    else if (value.length > 100) {
      try {
        const pqBytes = decodeBase64(value.trim());
        if (pqBytes.length === 1184) {
          pqLockBase64 = encodeBase64(pqBytes);
        } else if (pqBytes.length === 2496) {
          // KL Detected: Extract ML-KEM portion [0-1184]
          pqLockBase64 = encodeBase64(pqBytes.slice(0, 1184));
        }
      } catch (e) { console.error("Standalone PQ failed."); }
    }

    if (!classicLock && !pqLockBase64) {
      showStatusMsg("Invalid Lock Format", "bad");
      return;
    }

    const existing = locDir[name] || {};
    locDir[name] = {
      lock: classicLock || existing.lock || name,
      pqlock: pqLockBase64 || existing.pqlock || null,
      ro: existing.ro || null
    };

    await syncLocDir(locDir);
  }

  document.getElementById("new-lock-name").value = "";
  document.getElementById("new-lock-value").value = "";
  renderDirectory();
});

// Listen for close event
window.addEventListener("closeDirectory", () => {
  // Ensure directory card is hidden (redundant but safe)
  const dirCard = document.getElementById('directory-card');
  if (dirCard) dirCard.classList.add('hidden');

  // If we're in manual file mode, ensure the crypto UI is visible
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

// 1. Define the variable outside the object
let previousVisibleCards = [];

window.DirectoryEditor = {
  renderDirectory,
  setMode,
  setHost,
  // In directory_editor.js
  open: () => {
    const cards = document.querySelectorAll(".card");
    previousVisibleCards = [];
    cards.forEach((card) => {
      // Check if it's visible (not hidden)
      if (window.getComputedStyle(card).display !== "none" && !card.classList.contains("hidden")) {
        previousVisibleCards.push(card.id);
      }
      card.classList.add("hidden");
    });

    const masterSection = document.getElementById("master-password-section");
    if (masterSection && !masterSection.classList.contains("hidden")) {
      previousVisibleCards.push("master-password-section");
    }
    if (masterSection) masterSection.classList.add("hidden");

    document.getElementById("directory-card").classList.remove("hidden");
    renderDirectory();
  },

  close: () => {
    document.getElementById("directory-card").classList.add("hidden");

    previousVisibleCards.forEach((id) => {
      const el = document.getElementById(id);
      if (el) {
        el.classList.remove("hidden");
      }
    });

    window.dispatchEvent(new CustomEvent("closeDirectory"));
  },
};

// For debugging: Display all sync storage in console
function displaySync() {
  chrome.storage.sync.get(null, (items) => {
    chrome.storage.sync.get(null, (items) => {
      console.log('All sync storage:', items);
    });
  });
}

window.displaySync = displaySync;