/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

//functions for password generation 

// ===== SYNTHESIZE & FILL =====
// Helper function to build charset from user input
function buildAllowedCharset(inputStr) {
  const keywordMap = {
    numbers: "0123456789",
    numeric: "0123456789",
    alpha: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    alphanumeric:
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    hex: "0123456789abcdef",
  };

  let charset = "";

  // Split input into keywords and literals
  const parts = inputStr.match(/[a-z]+|[^a-z]+/gi) || [];

  parts.forEach((part) => {
    const lowerPart = part.toLowerCase();
    if (keywordMap[lowerPart]) {
      charset += keywordMap[lowerPart];
    } else {
      // Add literal characters as-is
      charset += part;
    }
  });

  // Remove duplicates
  charset = Array.from(new Set(charset.split("")))
    .join("")
    .replace(/\s+/g, "");

  return charset;
}

// Synth password generation handler
document.getElementById("do-synth").addEventListener("click", async () => {
  const masterPwd = document.getElementById("m-pass").value.trim();
  const serial = document.getElementById("serial").value.trim();
  const host = currentHost;

  if (!masterPwd) {
    showStatusMsg("Please enter your Master Key", "special");
    return;
  } else {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  const synthesized = await getSynthesizedPassword();

  // 1. Save data (now silent)
  saveHostData(host);

  // 2. Fill the page
  fillPasswordOnPage(synthesized);

  // 3. Set the correct status message
  if (window.isChangingPassword) {
    showStatusMsg("New password filled! Paste old password from clipboard into 'Current Password' field.", "special");
    // DO NOT reset the flag to false immediately here. 
    // If we reset it here, the async "Settings saved" might still catch it.
    // Let's reset it after a short delay.
    setTimeout(() => { window.isChangingPassword = false; }, 500);
  } else {
    showStatusMsg("Password filled and settings saved.", "good");
  }

  startMasterPwdTimeout();
});

// Helper to generate password without filling
async function getSynthesizedPassword() {
  const masterPwd = document.getElementById("m-pass").value.trim();
  const serial = document.getElementById("serial").value.trim();
  const host = currentHost;
  const allowedInput = document.getElementById("allowed-chars").value.trim();
  const lengthInput = document.getElementById("length-limit").value.trim();

  if (!masterPwd) {
    return null;
  } else {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  const defaultCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_-+=";
  let charset = allowedInput ? buildAllowedCharset(allowedInput) : defaultCharset;

  const hashBytes = wiseHash(masterPwd, host + serial);
  let bigIntHash = BigInt(0);
  for (let i = 0; i < hashBytes.length; i++) {
    bigIntHash = (bigIntHash << 8n) + BigInt(hashBytes[i]);
  }

  const base = BigInt(charset.length);
  let synthesized = "";
  while (bigIntHash > 0n) {
    const remainder = bigIntHash % base;
    synthesized = charset[Number(remainder)] + synthesized;
    bigIntHash = bigIntHash / base;
  }

  const length = lengthInput ? Math.min(parseInt(lengthInput), synthesized.length) : synthesized.length;
  return synthesized.slice(0, length);
}

// The "Change Password" button listener
document.getElementById("change-synth")?.addEventListener("click", async () => {
  const host = window.currentHost;
  const masterPwd = document.getElementById("m-pass")?.value.trim();
  let oldPwd = null;

  if (!masterPwd) {
    showStatusMsg("Please enter Master Key first.", "special");
    return;
  } else {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  // 1. Attempt to retrieve and decrypt from Vault (Pro Feature)
  if (window.checkProGate?.() && host) {
    const ciphertext = await getVaultPwd(host);
    if (ciphertext) {
      try {
        const key = wiseHash(masterPwd, host);
        const decryptedBytes = keyDecrypt(ciphertext, key);
        const plaintext = LZString.decompressFromUint8Array(decryptedBytes);

        if (plaintext) {
          oldPwd = confirm("You have a stored password. Do you want that one? If you cancel, a synthesized one with current parameters will be used") ? plaintext : null;
        }
      } catch (e) {
        console.error("Change-synth vault decryption error:", e);
        // Fallback happens naturally if oldPwd remains null
      }
    }
  }

  // 2. Fallback to synthesized password
  if (!oldPwd) {
    oldPwd = await getSynthesizedPassword();
  }

  if (!oldPwd) {
    showStatusMsg("Please enter your Master Key first.", "special");
    return;
  }

  try {
    // Copy the decrypted/synthesized password and flag for update
    await copyAndScheduleClear(oldPwd);
    window.isChangingPassword = true;
    showStatusMsg("Old password copied! Change serial and click 'Synthesize and Fill'.", "special");
  } catch (err) {
    showStatusMsg("Failed to copy to clipboard.", "bad");
  }
});

// sends password to content script to fill into page
async function fillPasswordOnPage(password) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  // Try to fill on page
  chrome.tabs.sendMessage(tab.id, { type: "FILL_PASSWORD", password }, async (response) => {
    // If content script says "no field found" or doesn't respond
    if (chrome.runtime.lastError || !response || !response.success) {
      try {
        await copyAndScheduleClear(password);
        showStatusMsg("No password field found. Password copied to clipboard instead.", "special");
      } catch (err) {
        showStatusMsg("Failed to fill or copy password.", "bad");
      }
    } else {
      // Success on page
    }
  });
}

// ===== VAULT PASSWORD MANAGEMENT =====

async function getVaultPwd(host) {
  return new Promise((resolve) => {
    chrome.storage.sync.get(host, (data) => {
      resolve(data?.[host]?.crypt?.pwd || null);
    });
  });
}

async function setVaultPwd(host, encryptedPwd) {
  return new Promise((resolve) => {
    chrome.storage.sync.get(host, (data) => {
      const item = data[host] || {};
      item.crypt = item.crypt || {};
      item.crypt.pwd = encryptedPwd || null; // null = delete
      chrome.storage.sync.set({ [host]: item }, resolve);
    });
  });
}

document.getElementById("useVaultPwd").addEventListener("click", async () => {
  //pro feature
  if (!window.checkProGate()) return;

  if (!currentHost) {
    showStatusMsg("No active host detected.", "special");
    return;
  }

  const masterPwd = document.getElementById("m-pass")?.value.trim();
  if (!masterPwd) {
    showStatusMsg("Please enter Master Key first.", "special");
    return;
  }

  const stored = await getVaultPwd(currentHost);

  if (stored) {
    handleVaultOptions(stored, currentHost);
  } else {
    showVaultPrompt(currentHost);
  }
});

async function handleVaultOptions(ciphertext, host) {
  const masterPwd = document.getElementById("m-pass")?.value.trim();
  if (!masterPwd) {
    showStatusMsg("Please enter Master Key first.", "special");
    return;
  } else {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  try {
    const salt = wiseHash(masterPwd, host);
    const decrypted = LZString.decompressFromUint8Array(keyDecrypt(ciphertext, salt));

    if (decrypted) {
      const action = confirm(
        "Use stored password? (OK=use, Cancel=change/delete)",
      );
      if (action) {
        fillPasswordOnPage(decrypted);
      } else {
        showVaultPrompt(host); // User can change or DELETE
      }
    } else {
      showStatusMsg("Decryption failed. Wrong Master Key?", "bad");
    }
  } catch (e) {
    console.error("Vault options error:", e);
    showStatusMsg("Decryption error. Check Master Key.", "bad");
  }
}

function showVaultPrompt(host) {
  const pwd = prompt(
    "Enter password to store for this site.\nTo delete stored password, enter: DELETE",
  );

  if (pwd === null) return; // User cancelled

  if (pwd === "DELETE" || pwd === "delete") {
    deleteVaultPwd(host);
    return;
  }

  if (pwd.trim() === "") {
    showStatusMsg("Password not stored.", "special");
    return;
  }

  encryptAndStoreVaultPwd(pwd, host);
}

async function encryptAndStoreVaultPwd(plainPwd, host) {
  const masterPwd = document.getElementById("m-pass")?.value.trim();
  if (!masterPwd) {
    showStatusMsg("Please enter Master Key first.", "special");
    return;
  } else {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  try {
    const key = wiseHash(masterPwd, host);
    const ciphertext = keyEncrypt(LZString.compressToUint8Array(plainPwd), key);

    await setVaultPwd(host, ciphertext);
    showStatusMsg("Password stored.", "info");

    fillPasswordOnPage(plainPwd);
  } catch (e) {
    console.error("Vault encrypt error:", e);
    showStatusMsg("Error storing password: " + e.message, "bad");
  }

  await updateVaultStatus();
}

async function deleteVaultPwd(host) {
  await setVaultPwd(host, null);
  showStatusMsg("Stored password deleted.", "info");

  await updateVaultStatus();
}

async function updateVaultStatus() {
  const statusEl = document.getElementById("mainMsg");

  if (!statusEl || !currentHost) return;

  const stored = await getVaultPwd(currentHost);

  if (stored) {
    statusEl.textContent = "Stored password available.";
  } else {
    statusEl.textContent = ""; // Clear if none
  }
}