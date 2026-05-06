/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

/**
 * sidepanel_notes.js
 * Logic for the Encrypted Site Notes UI
 */

// 1. Save Note

async function saveNote(type = "notes") {
  const noteText = document.getElementById("site-notes-input").value;
  if (!noteText) {
    showStatusMsg('Nothing to save', 'info')
    return;
  }

  //pro feature
  if (type === 'notes' && !window.checkProGate()) return;

  const masterPwd = document.getElementById("m-pass").value.trim();
  if (!masterPwd) {
    cards.masterSection.classList.remove("hidden");
    document.getElementById("m-pass").focus();
    return;
  } else {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  try {
    const key = wiseHash(masterPwd, currentHost);
    const encryptedNote = keyEncrypt(LZString.compressToUint8Array(noteText), key);

    const data = await chrome.storage.sync.get([currentHost]);
    const hostData = data[currentHost] || {};
    hostData.crypt = hostData.crypt || {};

    // Store in the specified key (notes or once)
    hostData.crypt[type] = encryptedNote;

    await chrome.storage.sync.set({ [currentHost]: hostData });

    showStatusMsg(
      type === "once" ? "Read-once note saved." : "Notes saved.",
      "good",
    );
  } catch (e) {
    showStatusMsg("Error: " + e.message, "bad");
  }
}

// 2. Clear Note Storage
async function clearNotes() {
  if (
    !confirm("Delete the saved note for this site? This cannot be undone.")
  ) {
    return;
  }

  try {
    const data = await chrome.storage.sync.get([currentHost]);
    const hostData = data[currentHost] || {};

    if (hostData.crypt) {
      hostData.crypt.notes = null;
      await chrome.storage.sync.set({ [currentHost]: hostData });
    }

    document.getElementById("site-notes-input").value = "";
    showStatusMsg("Note deleted.", "info");
  } catch (e) {
    showStatusMsg("Error deleting note: " + e.message, "bad");
  }
}

function unlockNotes() {
  const masterPwd = document.getElementById("m-pass").value.trim();
  if (!masterPwd) {
    cards.masterSection.classList.remove("hidden");
    document.getElementById("m-pass").focus();
    return;
  }
  unlockAndDecryptNote();
}

async function enterNotesMode(host) {
  if (!host) return;

  // 1. Fetch the host object from sync storage
  const data = await chrome.storage.sync.get([host]);
  const hostData = data[host]?.crypt;

  // 2. Detection: Check for Permanent (.notes) OR Read-Once (.once)
  const hasContent = hostData && (hostData.notes || hostData.once);

  const editorArea = document.getElementById("notes-editor");
  const lockedArea = document.getElementById("notes-locked");

  if (hasContent) {
    // Encrypted content exists: Show the "Locked" view
    editorArea.classList.add("hidden");
    lockedArea.classList.remove("hidden");

    // Auto-unlock attempt: If Master Key is already in the input, decrypt now
    const masterPwd = document.getElementById("m-pass")?.value.trim();
    if (masterPwd) {
      unlockAndDecryptNote();
    } else {
      // Otherwise, make sure the Master Key section is visible so they can type it
      document.getElementById('master-password-section')?.classList.remove('hidden');
    }
  } else {
    // No content: Show the empty editor for new note creation
    editorArea.classList.remove("hidden");
    lockedArea.classList.add("hidden");
    document.getElementById("site-notes-input").value = "";

    // Ensure the "Read-Once" UI checkbox (if any) is reset for the new session
    const onceCheck = document.getElementById("check-once");
    if (onceCheck) onceCheck.checked = false;
  }
}

async function unlockAndDecryptNote() {
  const masterPwd = document.getElementById("m-pass").value.trim();
  if (!masterPwd) {
    cards.masterSection.classList.remove("hidden");
    document.getElementById("m-pass").focus();
    return;
  } else {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  try {
    const data = await chrome.storage.sync.get([currentHost]);
    const hostData = data[currentHost] || {};
    const key = wiseHash(masterPwd, currentHost);

    let finalDisplay = "";
    let deletedOnce = false;

    // 1. Decrypt Regular Note if it exists
    if (hostData.crypt?.notes) {
      finalDisplay += LZString.decompressFromUint8Array(await keyDecrypt(hostData.crypt.notes, key));
    }

    // 2. Decrypt Read-Once Note if it exists
    if (hostData.crypt?.once) {
      const onceText = LZString.decompressFromUint8Array(await keyDecrypt(hostData.crypt.once, key));
      finalDisplay +=
        (finalDisplay ? "\n\n--- READ-ONCE NOTE ---\n\n" : "") + onceText;

      // Mark for deletion
      hostData.crypt.once = null;
      deletedOnce = true;
    }

    if (!finalDisplay && !deletedOnce) {
      enterNotesMode(currentHost);
      return;
    }

    // 3. Update UI and Storage
    document.getElementById("site-notes-input").value = finalDisplay;
    document.getElementById("notes-locked").classList.add("hidden");
    document.getElementById("notes-editor").classList.remove("hidden");

    if (deletedOnce) {
      await chrome.storage.sync.set({ [currentHost]: hostData });
      showStatusMsg("Read-once note deleted.", "info");
    } else {
      showStatusMsg("Notes decrypted.", "good");
    }

  } catch (e) {
    console.error("Decryption failed:", e);
    showStatusMsg("Decryption failed. Check your Master Key.", "bad");
  }
}

/**
 * Removes notes/once-notes for a host while preserving other data.
 */
async function deleteNotesForHost(host) {
  return new Promise((resolve) => {
    chrome.storage.sync.get(host, (data) => {
      const item = data[host] || {};
      if (item.crypt) {
        delete item.crypt.notes;
        delete item.crypt.once;
      }
      chrome.storage.sync.set({ [host]: item }, () => {
        showStatusMsg("Legacy notes purged.", "info");
        // Reset UI state to allow fresh entry
        document.getElementById("notes-locked").classList.remove("hidden");
        document.getElementById("notes-editor").classList.add("hidden");
        document.getElementById("site-notes-input").value = "";
        resolve();
      });
    });
  });
}