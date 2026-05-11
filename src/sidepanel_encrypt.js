/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

//functions for encryption side panel

/**
 * Builds the binary header for the encrypted message.
 * @param {boolean} isAnon - Whether it's anonymous mode.
 * @param {number} recipientCount - Number of recipients.
 * @param {Uint8Array} nonce15 - The 15-byte nonce.
 * @param {Uint8Array | null} ephemeralPub - Ephemeral public key for anonymous mode (32 bytes).
 * @param {string} decoyPlaintext - The optional decoy message text.
 * @param {Uint8Array} mySecretKey - The sender's secret key (for decoy encryption).
 * @returns {Uint8Array} The constructed header.
 */
/**
 * Builds the binary header for the encrypted message.
 * Markers: 0 (A), 72 (S), 56 (O), 1 (B), 73 (T)
 */
async function buildBinaryHeader(mode, recipientCount, nonce15, ephemeralPub, decoyPlaintext, mySecretKey) {
  // Mode 0 (Classic Anonymous) includes 32-byte ECC key (117 + 32 = 149)
  // All other modes (1, 72, 73, 56, 128) use 117 bytes
  const headerSize = ephemeralPub ? 149 : 117;
  const outHeader = new Uint8Array(headerSize);

  outHeader[0] = mode;
  outHeader[1] = recipientCount & 0xFF;
  outHeader.set(nonce15, 2);

  // Decoy/Padding (100 bytes)
  let padding;
  if (decoyPlaintext && decoyPlaintext.length > 0) {
    padding = await decoyEncrypt(decoyPlaintext, mySecretKey);
  } else {
    padding = nacl.randomBytes(100);
  }
  outHeader.set(padding, 17);

  // ECC Ephemeral Key (only for Mode 0)
  if (ephemeralPub) {
    outHeader.set(ephemeralPub, 117);
  }

  return outHeader;
}

/**
 * Encrypts the message key for a single recipient, handling standard and Read-once modes.
 * In Read-once mode, it manages a per-recipient state machine to ensure Perfect Forward Secrecy (PFS).
 * 
 * @param {Uint8Array} recipientSigningPub - Recipient's permanent Edwards public key.
 * @param {Uint8Array} nonce24 - 24-byte nonce used for the entire message.
 * @param {Uint8Array} msgKey - 32-byte random key that encrypts the actual message body.
 * @param {Uint8Array} mySecretKey - Sender's permanent Curve25519 secret key.
 * @param {string} storageKey - Key used to encrypt locDir state for this recipient.
 * @param {number} mode - 0 (Anonymous), 72 (Signed), 56 (Read-once).
 * @param {string} recipientEmail - Email used to look up ephemeral state in locDir.
 */
function encryptForRecipientWithLock(recipientSigningPub, nonce24, msgKey, mySecretKey, storageKey, mode, recipientEmail) {
  const recipientPub = ed2curve.convertPublicKey(recipientSigningPub);
  if (!recipientPub) return null;

  // --- 0. NAME RESOLUTION ---
  const targetLockB36 = encodeUint8ToBase36(recipientSigningPub);
  let resolvedId = recipientEmail;
  for (const [id, data] of Object.entries(window.locDir)) {
    if (data.lock === targetLockB36) {
      resolvedId = id;
      break;
    }
  }

  // --- 1. STANDARD MODES (0, 72) ---
  if (mode === 72 || mode === 0) {
    const sharedKey = nacl.box.before(recipientPub, mySecretKey);
    const cipher2 = nacl.secretbox(msgKey, nonce24, sharedKey);
    const idTag = nacl.secretbox(recipientSigningPub, nonce24, sharedKey).slice(0, 8);
    return { slot: concatUi8([idTag, cipher2]), newState: null };
  }

  // --- 2. READ-ONCE MODE (56) ---
  else if (mode === 56) {
    if (!window.locDir[resolvedId]) {
      window.locDir[resolvedId] = {
        lock: targetLockB36,
        ro: { lastkey: null, lastlock: null, turn: null }
      };
    }

    const entry = JSON.parse(JSON.stringify(window.locDir[resolvedId]));
    if (!entry.ro) entry.ro = { lastkey: null, lastlock: null, turn: null };

    const { turn: turnstring, lastkey: lastKeyCipher, lastlock: lastLockCipher } = entry.ro;

    // FIX: isReset should only be true if we have no state at all or were explicitly told to reset.
    // If Bob has a turnstring of 'lock', he is NOT in reset mode.
    const isReset = (turnstring === 'reset' || !turnstring);
    const isUnlocking = (turnstring === 'unlock');

    let typeByte;
    let currentSecret;
    const nextSecret = nacl.randomBytes(32);

    if (isReset) {
      typeByte = new Uint8Array([172]);
      // Reuse the same secret if we are just re-sending the same reset message
      currentSecret = (lastKeyCipher && turnstring === 'reset') ? keyDecrypt(lastKeyCipher, storageKey, true) : nextSecret;
    } else {
      typeByte = isUnlocking ? new Uint8Array([164]) : new Uint8Array([160]);
      // If Bob is replying for the first time, he doesn't have a lastkey yet; he uses nextSecret.
      currentSecret = lastKeyCipher ? keyDecrypt(lastKeyCipher, storageKey, true) : nextSecret;
    }

    const activeBobLock = (isReset || !lastLockCipher)
      ? recipientPub
      : keyDecrypt(lastLockCipher, storageKey, true);

    if (!activeBobLock || !currentSecret) return null;

    const idKey = nacl.box.before(activeBobLock, mySecretKey);
    const sharedKey = nacl.box.before(activeBobLock, currentSecret);

    const cipher2 = nacl.secretbox(msgKey, nonce24, sharedKey);
    const idTag = nacl.secretbox(recipientSigningPub, nonce24, idKey).slice(0, 8);

    const secretToPublicize = (turnstring === 'lock' || isReset) ? nextSecret : currentSecret;
    const newLockCipher = nacl.secretbox(makePub(secretToPublicize), nonce24, idKey);

    // If we are in 'lock' (ready to reply), we generate and save a NEW local secret
    if (turnstring === 'lock' || isReset) {
      entry.ro.lastkey = keyEncrypt(nextSecret, storageKey);
    }

    // --- THE FIX: ADVANCE TURN ---
    // If we were in 'lock' and we hit send, we are now 'unlock' (waiting for Bob).
    // If we were in 'reset' and we hit send, we stay 'reset' until Bob accepts the handshake.
    entry.ro.turn = isReset ? 'reset' : 'unlock';

    return {
      slot: concatUi8([idTag, cipher2, typeByte, newLockCipher]),
      newState: { id: resolvedId, data: entry } // Ensure caller uses this ID
    };
  }
  return null;
}

/**
 * SYMMETRIC (G-Mode) encryption handler
 * Triggered when a password is provided for non-recipient encryption
 */
async function handleSymmetricEncryption(msgUint8, fileName = null) {
  const pwd = prompt("Enter a Shared Key for Symmetric encryption:");
  if (!pwd) {
    return null;
  } else {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  const hKey = parseHumanKey(pwd);
  if (hKey) {
    // Human mode remains text-based and atomic
    const fullBuf = (msgUint8 instanceof Blob) ? new Uint8Array(await msgUint8.arrayBuffer()) : msgUint8;
    const plainText = new TextDecoder().decode(fullBuf);
    const cipherText = humanEncryptDecrypt(plainText, hKey, true);
    return { finalBin: new TextEncoder().encode(cipherText), modeLabel: "HUMAN" };
  }

  // Just return the derived key material for standard Symmetric
  const nonce15 = nacl.randomBytes(15);
  const encryptionKey = wiseHash(pwd, encodeBase64(nonce15));

  return {
    symKey: encryptionKey,
    nonce15: nonce15,
    modeLabel: "SYMMETRIC"
  };
}

// --- Main Encryption Trunk ---
async function startEncryption() {
  const mainBox = document.getElementById('mainBox');
  const lockList = document.getElementById('lockList');

  // NEW: Get the unified state first
  const state = getEncryptionState();

  // RE-ASSIGN: Map the new UI state back to your existing variable names
  const isAnon = (state.mode === 'anon');
  const isOnce = (state.mode === 'readonce');
  const isCertified = (state.mode === 'certified');

  // These retain their original IDs as you requested
  const includeLock = document.getElementById('add-lock-check');
  const decoyToggle = document.getElementById('hidden-msg-check');
  const decoyArea = document.getElementById('decoyMessageArea');

  try {
    let msgUint8;
    const rawHTML = mainBox.innerHTML.trim();

    // 1. Unified Logic: If box is empty, offer Folder Key
    if (!rawHTML) {
      if (window.PB_PRO_STATUS && window.PB_PRO_STATUS.active) {
        //Folder keys enabled in pro
        const promptMsg = window.activeFolderKey
          ? "Compose box is empty. Use the ACTIVE Folder Key as payload?"
          : "Compose box is empty. Generate a NEW 32-byte Folder Key?";

        if (confirm(promptMsg)) {
          // Use active key if it exists, otherwise generate new
          msgUint8 = window.activeFolderKey || nacl.randomBytes(32);
        } else {
          return;
        }
      } else {
        showStatusMsg('Nothing to encrypt', 'info');
        return
      }
    } else {
      msgUint8 = LZString.compressToUint8Array(rawHTML);
    }

    // UNIFIED MODE MAPPING
    let mode;
    switch (state.mode) {
      case 'anon': mode = 0; break;
      case 'pq-anon': mode = 1; break;
      case 'readonce': mode = 56; break;
      case 'signed': mode = 72; break;
      case 'pq-signed': mode = 73; break;
      case 'certified': mode = 150; break; // Ensure this matches your UI value
      default: mode = 72; break;
    }

    //pro feature: modes 1, 56, 73, 150
    if ([1, 56, 73, 150].includes(mode)) {
      if (!window.checkProGate()) return;
    }

    const masterPwd = document.getElementById('m-pass')?.value.trim();
    const myEmail = document.getElementById("user-email")?.value.trim() || "";
    const hasSelectedRecipients = lockList.selectedOptions.length > 0;

    const isStandardMode = !window.activePadBin && !window.activeFolderKey;

    if (isStandardMode && [72, 73, 56, 150].includes(mode) && hasSelectedRecipients) {
      if (!myEmail) {
        showStatusMsg("Email required for key derivation.", "special");
        document.getElementById("user-email")?.focus();
        return;
      }
      if (!masterPwd) {
        showStatusMsg("Master Key required.", "bad");
        document.getElementById('m-pass').focus();
        return;
      }
      else {
        showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
        await new Promise(r => setTimeout(r, 50));
      }
    }

    const settings = {
      selectedRecipients: Array.from(lockList.selectedOptions).map(o => o.value.trim()).filter(s => s),
      mode: mode, // This will now correctly be 150
      masterPwd: masterPwd,
      myEmail: myEmail,
      activeFolderKey: window.activeFolderKey,
      decoyText: (decoyToggle && decoyToggle.checked) ? decoyArea.value.trim() : ""
    };

    const result = await coreEncrypt(msgUint8, settings);
    if (!result) {
      return;
    }

    // --- NEW: USE THE UNIFIED FINALIZE FUNCTION ---
    await finalizeAndInject(result, settings.selectedRecipients.length);

    if (decoyArea) { decoyArea.value = ""; document.getElementById('decoyByteCount').textContent = "0"; }
    if (typeof startMasterPwdTimeout === "function") startMasterPwdTimeout();

  } catch (err) {
    console.error("Encryption Error:", err);
    showStatusMsg("Encryption failed: " + err.message, "bad");
  }
}

async function finalizeAndInject(result) {
  const mainBox = document.getElementById('mainBox');
  const decoyArea = document.getElementById('decoyMessageArea');
  const decoyToggle = document.getElementById('hidden-msg-check');
  const includeLock = document.getElementById('add-lock-check');

  const { finalBin, modeLabel, base36Lock, addLock } = result;

  // --- YOUR EXACT CODE BELOW ---
  let ciphertextB64 = (modeLabel === "HUMAN")
    ? new TextDecoder().decode(finalBin)
    : encodeBase64(finalBin).replace(/=+$/, '');

  let lockPrefix = "";

  if (addLock) {
    const forceLock = (modeLabel === "INVITATION");
    const optionalLock = (includeLock?.checked &&
      ["SIGNED", "ANONYMOUS", "READ ONCE", "SYMMETRIC", "FOLDER", "PQ SIGNED", "PQ ANONYMOUS"].includes(modeLabel));

    if (forceLock || optionalLock) {
      const hostData = await chrome.storage.sync.get([currentHost]);
      const myCrypt = hostData[currentHost]?.crypt || {};
      const myClassic = base36Lock || myCrypt.lock || "";

      if (myClassic) {
        let finalIdentity = myClassic;
        // Invitations are essentially a "PQ Mode" if the user has a PQ lock
        const isPQMode = modeLabel.startsWith("PQ") || modeLabel === "INVITATION";

        if (isPQMode && myCrypt.pqlock) {
          try {
            const pqBinary = decodeBase64(myCrypt.pqlock);
            const pqBase64 = encodeBase64(pqBinary);
            finalIdentity = `${myClassic}//////${pqBase64}`;
          } catch (e) { console.error(e); }
        }
        lockPrefix = finalIdentity + "//////";
      }
    }
  }

  // --- INJECTION LOGIC ---
  const wrapped = (lockPrefix + ciphertextB64).match(/.{1,80}/g).join("\n");

  // Logic to dynamically adjust armor based on lock presence
  const armorLabel = lockPrefix ? `${modeLabel} MESSAGE WITH LOCK` : `${modeLabel} MESSAGE`;

  let fullBlock = `<pre>\n----BEGIN PRIVACY BAR ${armorLabel}----==\n${wrapped}\n==----END PRIVACY BAR ${armorLabel}----\n</pre>`;

  if (modeLabel === "INVITATION") {
    // Add your onboarding text here!
    const onboarding = "Click the block below to add me to your contacts:\n\n";
    fullBlock = onboarding + fullBlock;
    if (typeof wrapInvitationText === 'function') fullBlock = wrapInvitationText(fullBlock);
  }

  // --- INJECTION LOGIC ---
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  chrome.tabs.sendMessage(tab.id, { type: "INSERT_ENCRYPTED_TEXT", text: "\n" + fullBlock + "\n", messageId: Date.now() }, async (response) => {
    if (response?.success) {
      if (mainBox) mainBox.innerHTML = "";
      showStatusMsg(`${modeLabel} generated successfully!`, "good");
    } else {
      if (mainBox) mainBox.innerHTML = fullBlock;
      showStatusMsg("Field not found. Text copied to box.", "special");
    }
  });

  if (decoyArea) { decoyArea.value = ""; }
}

/**
 * Formats the final message with onboarding instructions. This needs to be edited once the Extension gets listed and we have a stable URL to point to for the app and extension download.
 */
function wrapInvitationText(encryptedBlock) {
  return `
<div class="pb-invitation" style="font-family: sans-serif; line-height: 1.5; color: #333; max-width: 40rem;">
  <p style="font-size: 0.8rem;">The text below contains my <strong>Privacy Bar Lock</strong>. To start messaging securely, follow these steps:</p>
  
  <ol style="padding-left: 1.33rem; font-size: 0.8rem;">
    <li><strong>Install</strong> the Privacy Bar extension.</li>
    <li><strong>Reload</strong> this page to activate the extension.</li>
    <li><strong>Click</strong> the icon and set up your Master Key.</li>
    <li><strong>Click</strong> on the block of gibberish below.</li>
    <li><strong>Click</strong> the <strong>Decrypt</strong> button to save the Lock.</li>
  </ol>

  <p style="margin-bottom: 0.33rem; color: #666; font-size: 0.8rem;">My Public Lock:</p>
  <div style="padding: 0.67rem 0; border-top: 1px solid #eee; font-family: monospace; font-size: 0.8rem; word-break: break-all; color: #000;">
    ${encryptedBlock}
  </div>
</div>`.trim();
}

// --- Decoy Encryption Function ---

async function decoyEncrypt(plaintext) {
  const TOTAL_PADDING_LENGTH = 100;
  const NONCE_LENGTH = 9;

  try {
    if (!plaintext) return nacl.randomBytes(TOTAL_PADDING_LENGTH);

    const decoyKeyStr = prompt("Enter the secret key to encrypt the hidden message:");
    if (!decoyKeyStr) {
      return nacl.randomBytes(TOTAL_PADDING_LENGTH);
    } else {
      showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
      await new Promise(r => setTimeout(r, 50));
    }

    // 1. Fill 75 bytes with spaces (0x20)
    const finalPlaintext = new Uint8Array(75).fill(0x20);
    const textBytes = new TextEncoder().encode(plaintext);
    finalPlaintext.set(textBytes.subarray(0, Math.min(textBytes.length, 75)));

    // 2. Standard encryption
    const nonce = nacl.randomBytes(NONCE_LENGTH);
    const nonce24 = makeNonce24(nonce);
    const sharedKey = wiseHash(decoyKeyStr, encodeBase64(nonce));
    const cipher = nacl.secretbox(finalPlaintext, nonce24, sharedKey);

    // 3. Assemble: 9 (nonce) + 91 (cipher) = 100 bytes exactly
    return concatUi8([nonce, cipher]);

  } catch (e) {
    console.error("Decoy encryption failed:", e);
    return nacl.randomBytes(TOTAL_PADDING_LENGTH);
  }
}

// Bridge for File Encryption
/**
 * Bridge for File Encryption and Certification.
 * Standardizes the "Unified" header for file outputs while keeping 
 * UI-to-UI paths naked.
 */
async function processFileEncryption(fileBlob, outName, targetMode = null) {
  try {
    const state = getEncryptionState();
    const decoyArea = document.getElementById('decoyMessageArea');

    // 1. Determine Mode: Use the passed targetMode if available, otherwise fallback to UI
    let mode = targetMode;
    if (mode === null) {
      mode = 72;
      if (state.mode === 'anon') mode = 0;
      if (state.mode === 'pq-anon') mode = 1;
      if (state.mode === 'pq-signed') mode = 73;
      if (state.mode === 'readonce') mode = 56;
      if (state.mode === 'certified') mode = 150;
      if (state.mode === 'folder' || state.mode === 'symmetric') mode = 128;
    }

    const isCertifiedMode = (mode === 150);
    const internalName = outName.toLowerCase().endsWith('.pbx') ? outName.slice(0, -4) : outName;
    let finalOutName = outName.toLowerCase().endsWith('.pbx') ? outName : outName + '.pbx';
    let finalBin;

    // 2. Aggressive Recipient Capture
    // We check the state first, then the DOM as a backup
    let recipients = state.recipients || [];
    if (recipients.length === 0) {
      const lockList = document.getElementById('lockList');
      if (lockList && lockList.selectedOptions) {
        recipients = Array.from(lockList.selectedOptions).map(o => o.value.trim()).filter(s => s);
      }
    }

    // AUTO-SWITCH: If no recipients found, force Symmetric mode to prevent coreEncrypt confusion
    if (recipients.length === 0 && mode !== 0 && mode !== 1) {
      mode = 128;
    }

    // --- BRANCH A: CERTIFICATION ---
    if (isCertifiedMode) {
      const fileUint8 = new Uint8Array(await fileBlob.arrayBuffer());
      const unifiedBytes = prepareUnifiedPlaintext(fileUint8, internalName);

      const result = await encryptCertifiedMode(new Blob([unifiedBytes]), {
        masterPwd: document.getElementById('m-pass')?.value.trim(),
        myEmail: document.getElementById("user-email")?.value.trim(),
        decoyText: state.useHidden ? decoyArea.value.trim() : ""
      });

      if (!result) return;
      finalBin = result.finalBin;
    }

    // --- BRANCH B: ENCRYPTION ---
    else {
      const masterPwd = document.getElementById('m-pass')?.value.trim();
      const myEmail = document.getElementById("user-email")?.value.trim() || "";
      const isStandardMode = !window.activePadBin && !window.activeFolderKey;

      // Identity Guard
      if (isStandardMode && mode !== 0 && mode !== 1 && mode !== 128) {
        if (!masterPwd) {
          showStatusMsg("Master Key required.", "bad");
          document.getElementById('m-pass').focus();
          return;
        }
        if (!myEmail) {
          showStatusMsg("Email required for key derivation.", "special");
          document.getElementById("user-email")?.focus();
          return;
        }
      }

      // Metadata Wrapping (Type 2+)
      const fileUint8 = new Uint8Array(await fileBlob.arrayBuffer());
      const wrappedPayload = prepareUnifiedPlaintext(fileUint8, internalName);

      const settings = {
        selectedRecipients: recipients, // Use our verified list
        mode: mode,
        masterPwd: masterPwd,
        myEmail: myEmail,
        activeFolderKey: window.activeFolderKey,
        decoyText: state.useHidden ? decoyArea.value.trim() : "",
        fileName: null
      };

      const result = await coreEncrypt(wrappedPayload, settings);
      if (!result || !result.finalBin) return;

      finalBin = result.finalBin;
    }

    // --- 3. OUTPUT ---
    const imgPreview = document.getElementById('stego-image-preview');
    if (imgPreview && imgPreview.src && imgPreview.src.length > 10) {
      const stegoBin = (finalBin instanceof Blob) ? new Uint8Array(await finalBin.arrayBuffer()) : finalBin;
      await attachBlobToImage(stegoBin);
      showStatusMsg("Encrypted file attached to image!", "good");
    } else {
      triggerDownload(finalBin, finalOutName);
      showStatusMsg(`Encrypted file saved: ${finalOutName}`, "good");
    }

    if (decoyArea) decoyArea.value = "";
    if (typeof startMasterPwdTimeout === "function") startMasterPwdTimeout();
    return true;

  } catch (err) {
    console.error("File Encryption Error:", err);
    showStatusMsg("Action failed: " + err.message, "bad");
  }
}

function resolveToLocks(input, finalLocks, locDir, myLock) {
  // 1. Clean and split the input list
  const items = input.split(",").map(i => i.trim()).filter(i => i.length > 0);

  for (const item of items) {
    const entry = locDir[item];

    if (entry) {
      // 2. If it's a nested list (comma-separated locks in the entry), recurse
      if (entry.lock && entry.lock.includes(",")) {
        resolveToLocks(entry.lock, finalLocks, locDir, myLock);
      } else {
        // 3. Add the NAME (the key) to the set, not the lock string.
        // This keeps PQ-only users unique.
        finalLocks.add(item);
      }
    } else {
      // 4. Fallback for raw input/pasted locks not in the directory
      finalLocks.add(item);
    }
  }
}

/**
 * FULL FUNCTION: coreEncrypt
 * Main dispatcher for all encryption modes.
 * Priority: Pad Mode > Folder Mode > Certified > Standard Recipients.
 */
async function coreEncrypt(msgUint8, settings) {
  // 1. PAD MODE (Absolute Override)
  if (window.activePadBin) {
    return await encryptPadMode(msgUint8, settings);
  }

  // 2. FOLDER MODE (Identity Override)
  // Priority: If a Folder Key is active, it takes precedence over recipients.
  if (settings.activeFolderKey) {
    return await encryptSymmetricMode(msgUint8, settings);
  }

  // 3. CERTIFIED MODE (ECC Signature)
  if (settings.mode === 150) {
    return await encryptCertifiedMode(msgUint8, settings);
  }

  // 4. SYMMETRIC MODE (0 Recipients, No Folder Key)
  if (settings.selectedRecipients.length === 0) {
    return await encryptSymmetricMode(msgUint8, settings);
  }

  // 5. RECIPIENT MODES (Signed, Anonymous, Read-Once, PQ)
  return await encryptRecipientMode(msgUint8, settings);
}

/**
 * FULL FUNCTION: encryptPadMode
 */
async function encryptPadMode(msgUint8, settings) {
  const pad = window.activePadBin;
  const nonce15 = nacl.randomBytes(15);
  const padding = (settings.decoyText?.trim()) ? await decoyEncrypt(settings.decoyText) : nacl.randomBytes(100);

  let seedHash;
  if (window.activePadBin instanceof Blob) {
    const p = window.activePadBin;
    const size = p.size;
    const sampleSize = 256 * 1024; // 256KB per sample

    // Sample from Start, Middle, and End
    const start = new Uint8Array(await p.slice(0, sampleSize).arrayBuffer());
    const mid = new Uint8Array(await p.slice(Math.floor(size / 2), Math.floor(size / 2) + sampleSize).arrayBuffer());
    const end = new Uint8Array(await p.slice(size - sampleSize, size).arrayBuffer());

    seedHash = await sha512Uint8(concatUi8([nonce15, start, mid, end]));
  } else {
    seedHash = await sha512Uint8(concatUi8([nonce15, window.activePadBin]));
  }

  let start64 = 0n;
  for (let i = 0; i < 8; i++) start64 = (start64 << 8n) | BigInt(seedHash[i]);
  let padCursor = Number(start64 % BigInt(pad.length || 1));

  const { chunk: hmacPadChunk, nextIndex: hmacNextIndex } = await findPadChunk(pad, padCursor, 512, { step: 64 });
  const hmacKeyRaw = await sha512Uint8(hmacPadChunk);
  const hmacKey = await crypto.subtle.importKey("raw", hmacKeyRaw, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  padCursor = hmacNextIndex;

  const results = [new Uint8Array([164]), nonce15, padding];
  const isBlob = (msgUint8 instanceof Blob);
  const nameBytes = settings.fileName ? new TextEncoder().encode(settings.fileName) : new Uint8Array(0);
  const meta = nameBytes.length > 0 ? concatUi8([new Uint8Array([nameBytes.length]), nameBytes]) : new Uint8Array(0);

  const source = (nameBytes.length > 0) ? (isBlob ? new Blob([meta, msgUint8]) : concatUi8([meta, msgUint8])) : msgUint8;
  const sourceSize = (source instanceof Blob) ? source.size : source.length;
  const FILE_CHUNK = 64 * 1024;
  let currentPos = 0;

  while (currentPos < sourceSize) {
    if (currentPos % (FILE_CHUNK * 10) === 0) {
      showStatusMsg(`Generating Pad Cipher: ${Math.round((currentPos / sourceSize) * 100)}%`, "info");
    }
    const dataToRead = Math.min(sourceSize - currentPos, FILE_CHUNK);
    const plainChunk = (source instanceof Blob)
      ? new Uint8Array(await source.slice(currentPos, currentPos + dataToRead).arrayBuffer())
      : source.slice(currentPos, currentPos + dataToRead);

    if (plainChunk.length === 0) break;

    const cipherChunk = new Uint8Array(plainChunk.length);
    for (let offset = 0; offset < plainChunk.length; offset += 64) {
      const subSize = Math.min(64, plainChunk.length - offset);
      const { chunk: padChunk, nextIndex } = await findPadChunk(pad, padCursor, 512, { step: 64 });
      const keyMaterial = await sha512Uint8(padChunk);
      for (let j = 0; j < subSize; j++) cipherChunk[offset + j] = plainChunk[offset + j] ^ keyMaterial[j];
      padCursor = nextIndex;
    }

    const fullMac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, cipherChunk));
    results.push(cipherChunk, fullMac.slice(0, 32));
    currentPos += dataToRead;
  }

  return {
    finalBin: isBlob ? new Blob(results) : concatUi8(results),
    modeLabel: "PAD",
    addLock: false
  };
}

/**
 * FULL FUNCTION: encryptSymmetricMode
 * Now handles the actual chunking loop for both Folder and Symmetric paths.
 */
async function encryptSymmetricMode(msgUint8, settings) {
  let encryptionKey, nonce15, modeLabel, base36Lock = "";
  const isBlob = (msgUint8 instanceof Blob);

  if (settings.activeFolderKey) {
    encryptionKey = settings.activeFolderKey;
    nonce15 = nacl.randomBytes(15);
    modeLabel = "FOLDER";
    const storage = await chrome.storage.sync.get([currentHost]);
    base36Lock = storage[currentHost]?.crypt?.lock || "";
  } else {
    const deriv = await handleSymmetricEncryption(msgUint8, settings.fileName);
    if (!deriv) return null;
    if (deriv.modeLabel === "HUMAN") return deriv; // Exit for Human mode

    encryptionKey = deriv.symKey;
    nonce15 = deriv.nonce15;
    modeLabel = deriv.modeLabel;
  }

  const msgKey = nacl.randomBytes(32);
  const nonce24 = makeNonce24(nonce15);
  const padding = (settings.decoyText) ? await decoyEncrypt(settings.decoyText) : nacl.randomBytes(100);
  const encryptedSessionKey = nacl.secretbox(msgKey, nonce24, encryptionKey);
  const header = concatUi8([new Uint8Array([128]), nonce15, padding, encryptedSessionKey]);

  const results = [header];
  const PT_CHUNK = 64 * 1024;
  let currentPos = 0;
  let i = 0;

  if (isBlob) {
    while (currentPos < msgUint8.size) {
      if (i % 20 === 0) showStatusMsg(`Processing File: ${Math.round((currentPos / msgUint8.size) * 100)}%`, "info");
      let chunkData;
      if (i === 0 && settings.fileName) {
        const nameBytes = new TextEncoder().encode(settings.fileName);
        const meta = concatUi8([new Uint8Array([nameBytes.length]), nameBytes]);
        const dataToRead = Math.max(0, PT_CHUNK - meta.length);
        const fileBytes = new Uint8Array(await msgUint8.slice(0, dataToRead).arrayBuffer());
        chunkData = concatUi8([meta, fileBytes]);
        currentPos += dataToRead;
      } else {
        const dataToRead = Math.min(PT_CHUNK, msgUint8.size - currentPos);
        chunkData = new Uint8Array(await msgUint8.slice(currentPos, currentPos + dataToRead).arrayBuffer());
        currentPos += dataToRead;
      }
      if (chunkData.length === 0) break;

      const cNonce = new Uint8Array(nonce24);
      new DataView(cNonce.buffer).setUint32(20, i, false);
      results.push(nacl.secretbox(chunkData, cNonce, msgKey));
      i++;
    }
    return { finalBin: new Blob(results), modeLabel, base36Lock, addLock: true };
  } else {
    const cipher = nacl.secretbox(msgUint8, nonce24, msgKey);
    return { finalBin: concatUi8([header, cipher]), modeLabel, base36Lock, addLock: true };
  }
}

/**
 * FULL FUNCTION: encryptCertifiedMode
 * Unified engine for Marker 150 (ECC Signature).
 * Uses Chained Hashing for Blobs to match processVerification logic.
 */
async function encryptCertifiedMode(payloadBytes, settings) {
  const masterPwd = settings.masterPwd || document.getElementById('m-pass')?.value.trim();
  const myEmail = settings.myEmail || document.getElementById("user-email")?.value.trim();

  if (masterPwd) {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  // 1. Key Derivation
  const { storageKey } = await prepareCommonData(masterPwd, myEmail);
  const KeySgn = nacl.sign.keyPair.fromSeed(storageKey).secretKey;

  // 2. Padding/Decoy
  const padding = (settings.decoyText?.trim()) ? await decoyEncrypt(settings.decoyText) : nacl.randomBytes(100);

  const isBlob = (payloadBytes instanceof Blob);
  let signature;

  // 3. SIGNING LOGIC
  if (isBlob) {
    // --- FILE PATH: Chained Hashing (Matches processVerification) ---
    let runningHash = new Uint8Array(64).fill(0);
    const CHUNK = 64 * 1024;
    let pos = 0;

    while (pos < payloadBytes.size) {
      const chunk = new Uint8Array(await payloadBytes.slice(pos, pos + CHUNK).arrayBuffer());
      if (chunk.length === 0) break;
      runningHash = await sha512Uint8(concatUi8([runningHash, chunk]));
      pos += CHUNK;
    }
    signature = nacl.sign.detached(runningHash, KeySgn);
  } else {
    // --- TEXT PATH: Direct Signature ---
    signature = nacl.sign.detached(payloadBytes, KeySgn);
  }

  const marker = new Uint8Array([150]);

  return {
    finalBin: isBlob ? new Blob([marker, padding, signature, payloadBytes]) : concatUi8([marker, padding, signature, payloadBytes]),
    modeLabel: "CERTIFIED",
    addLock: false
  };
}

/**
 * FULL FUNCTION: encryptRecipientMode
 * Main engine for Anonymous (0), PQ Anonymous (1), Read-Once (56), Signed (72), and PQ Signed (73).
 * Handles chunked Blob processing for files and atomic state updates for PFS.
 */
async function encryptRecipientMode(msgUint8, settings) {
  const isPQ = (settings.mode === 1 || settings.mode === 73);
  const storage = await chrome.storage.sync.get(['locDir', currentHost]);
  const locDir = storage.locDir || {};
  const userData = storage[currentHost] || {};
  const pendingStateUpdates = []; // Atomically applied only on successful encryption

  // 1. IDENTITY & KEY DERIVATION
  let mySecretKey, ephemeralPub = null, common = null;

  if (settings.mode === 0) {
    // Mode 0: Classic Anonymous requires an Ephemeral ECC key pair
    const ephemeral = nacl.box.keyPair();
    mySecretKey = ephemeral.secretKey;
    ephemeralPub = ephemeral.publicKey;
    common = await prepareCommonData(settings.masterPwd, settings.myEmail || userData?.crypt?.email || "");
  } else {
    // Other modes use the permanent identity key derived from Master Key
    common = await prepareCommonData(settings.masterPwd, settings.myEmail || userData?.crypt?.email || "");
    mySecretKey = common.myKey;
  }

  const myLock = common?.base36Lock || userData?.crypt?.lock || "";
  const msgKey = nacl.randomBytes(32);
  const nonce15 = nacl.randomBytes(15);
  const nonce24 = makeNonce24(nonce15);

  // 2. RECIPIENT RESOLUTION
  const finalLocks = new Set();
  const resolve = (input) => resolveToLocks(input, finalLocks, locDir, myLock);
  for (const sel of settings.selectedRecipients) {
    if (sel.toLowerCase() === "me") {
      if (settings.mode !== 56 && myLock) finalLocks.add("Me");
    } else {
      resolve(sel);
    }
  }

  // 3. RECIPIENT SLOT GENERATION
  const recipientSlots = [];
  for (const identifier of finalLocks) {
    let entry = locDir[identifier];
    let recipientName = identifier;
    let lockB36 = (identifier === "Me") ? myLock : (entry ? entry.lock : identifier);

    // --- PQ ENCAPSULATION (Modes 1 & 73) ---
    if (isPQ) {
      const pubPQ = (recipientName === "Me") ? common.myPQPair?.publicKey : (entry?.pqlock ? decodeBase64(entry.pqlock) : null);
      if (pubPQ && pubPQ.length === 1184) {
        try {
          const { sharedSecret, cipherText } = noblePostQuantum.ml_kem768.encapsulate(pubPQ);
          const n2 = crypto.getRandomValues(new Uint8Array(24));
          recipientSlots.push(concatUi8([cipherText, n2, nacl.secretbox(msgKey, n2, sharedSecret)]));
          continue;
        } catch (e) { console.error("PQ failed for:", recipientName); }
      }
    }

    // --- CLASSIC ENCRYPTION (Modes 0, 72, 56) ---
    const recipientUint8 = decodeBase36ToUint8(lockB36);
    if (!recipientUint8) continue;

    let fallbackMode = settings.mode;
    if (settings.mode === 1) fallbackMode = 0;   // PQ-Anon falls back to Anon
    if (settings.mode === 73) fallbackMode = 72; // PQ-Signed falls back to Signed

    const result = encryptForRecipientWithLock(
      recipientUint8,
      nonce24,
      msgKey,
      mySecretKey,
      common.storageKey,
      fallbackMode,
      recipientName
    );

    if (result) {
      recipientSlots.push(result.slot);
      if (result.newState) {
        // Use the resolved ID (e.g. "Bob") instead of recipientName (e.g. "LockXYZ")
        pendingStateUpdates.push({
          name: result.newState.id,
          state: result.newState.data
        });
      }
    }
  }

  if (recipientSlots.length === 0) throw new Error("No recipients could be encrypted.");

  // 4. HEADER ASSEMBLY
  let outHeader = await buildBinaryHeader(settings.mode, recipientSlots.length, nonce15, ephemeralPub, settings.decoyText || "", mySecretKey);

  // Randomize slot order to prevent recipient position leaking
  recipientSlots.sort(() => Math.random() - 0.5).forEach(slot => {
    outHeader = concatUi8([outHeader, slot]);
  });

  // 5. PAYLOAD ENCRYPTION
  const isBlob = (msgUint8 instanceof Blob);
  const results = [outHeader];
  const PT_CHUNK = 64 * 1024;
  let runningHash = new Uint8Array(64).fill(0); // For Chained Hashing in Mode 73
  let currentPos = 0;
  let i = 0;

  if (isBlob) {
    // --- CHUNKED BLOB PATH ---
    while (currentPos < msgUint8.size) {
      if (i % 20 === 0) showStatusMsg(`Encrypting: ${Math.round((currentPos / msgUint8.size) * 100)}%`, "info");
      let chunkData;
      if (i === 0 && settings.fileName) {
        // Inject [NameLen][FileName] Metadata into the first chunk
        const nameBytes = new TextEncoder().encode(settings.fileName);
        const meta = concatUi8([new Uint8Array([nameBytes.length]), nameBytes]);
        const dataToRead = Math.max(0, PT_CHUNK - meta.length);
        const fileBytes = new Uint8Array(await msgUint8.slice(0, dataToRead).arrayBuffer());
        chunkData = concatUi8([meta, fileBytes]);
        currentPos += dataToRead;
      } else {
        const dataToRead = Math.min(PT_CHUNK, msgUint8.size - currentPos);
        chunkData = new Uint8Array(await msgUint8.slice(currentPos, currentPos + dataToRead).arrayBuffer());
        currentPos += dataToRead;
      }

      const cNonce = new Uint8Array(nonce24);
      new DataView(cNonce.buffer).setUint32(20, i, false); // Sequence Nonce

      const encrypted = nacl.secretbox(chunkData, cNonce, msgKey);
      results.push(encrypted);

      if (settings.mode === 73) {
        runningHash = await sha512Uint8(concatUi8([runningHash, encrypted]));
      }
      i++;
    }
  } else {
    // --- ATOMIC TEXT PATH ---
    const mainCipher = nacl.secretbox(msgUint8, nonce24, msgKey);
    results.push(mainCipher);

    if (settings.mode === 73) {
      // Single-lap hash starting with 64 zeros to match decrypter
      runningHash = await sha512Uint8(concatUi8([new Uint8Array(64).fill(0), mainCipher]));
    }
  }

  // 6. PQ SIGNATURE INJECTION (Mode 73)
  if (settings.mode === 73) {
    const sig = nacl.sign.detached(runningHash, nacl.sign.keyPair.fromSeed(common.storageKey).secretKey);
    results.splice(1, 0, sig); // Signature sits between header and payload
  }

  // 7. FINALIZATION & STATE SYNC
  for (const update of pendingStateUpdates) {
    window.locDir[update.name] = update.state;
  }
  if (pendingStateUpdates.length > 0) await syncLocDir(window.locDir);

  const modeLabels = { 0: "ANONYMOUS", 1: "PQ ANONYMOUS", 56: "READ ONCE", 72: "SIGNED", 73: "PQ SIGNED" };

  return {
    finalBin: isBlob ? new Blob(results) : concatUi8(results),
    modeLabel: modeLabels[settings.mode],
    base36Lock: common?.base36Lock || "",
    addLock: true
  };
}

async function encryptToFile() {
  if (!window.checkProGate()) return;

  const mainBox = document.getElementById('mainBox');
  const decoyArea = document.getElementById('decoyMessageArea');
  const state = getEncryptionState();

  let isFolderKey = false;
  let mode = 72;
  if (state.mode === 'anon') mode = 0;
  if (state.mode === 'pq-anon') mode = 1;
  if (state.mode === 'pq-signed') mode = 73;
  if (state.mode === 'readonce') mode = 56;
  if (state.mode === 'certified') mode = 150;
  if (state.mode === 'pad') mode = 164;
  if (state.mode === 'folder' || state.mode === 'symmetric') mode = 128;

  try {
    let msgUint8;
    // --- PAYLOAD UNIFICATION ---
    const unifiedResult = await getUnifiedPayload();

    if (!unifiedResult) {
      const promptMsg = window.activeFolderKey
        ? "Compose box is empty. Encrypt the ACTIVE Folder Key to this file?"
        : "Compose box is empty. Generate and encrypt a NEW random Folder Key?";

      if (!confirm(promptMsg)) return;
      const rawKey = window.activeFolderKey || nacl.randomBytes(32);
      msgUint8 = prepareUnifiedPlaintext(rawKey, "RAW_BINARY");
      isFolderKey = true;
    } else {
      msgUint8 = unifiedResult;
    }

    const settings = {
      selectedRecipients: state.recipients,
      mode: mode,
      masterPwd: document.getElementById('m-pass')?.value,
      myEmail: document.getElementById("user-email")?.value || "",
      fileName: null,
      activeFolderKey: window.activeFolderKey,
      decoyText: (state.useHidden) ? decoyArea.value.trim() : ""
    };

    const finalPayload = (mode === 150) ? new Blob([msgUint8]) : msgUint8;
    const result = await coreEncrypt(finalPayload, settings);
    if (!result) return;

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    let fileName = isFolderKey ? `folder_key_${timestamp}.pbx` : `privacy_bar_${timestamp}.htm.pbx`;

    // --- NEW: CAMO INTEGRATION ---
    let finalDownloadData = result.finalBin;

    if (window.checkProGate() && window.currentCoverBytes) {
      let imageBytes = new Uint8Array(window.currentCoverBytes);
      let eofIndex = -1;
      let extension = "jpg";

      // 1. Identify Format and EOF
      if (imageBytes[0] === 0xFF && imageBytes[1] === 0xD8) {
        extension = "jpg";
        const idx = findSequence(imageBytes, JPG_EOF);
        if (idx !== -1) eofIndex = idx + JPG_EOF.length;
      } else {
        extension = "png";
        const idx = findSequence(imageBytes, PNG_EOF);
        if (idx !== -1) eofIndex = idx + PNG_EOF.length;
      }

      // 2. Prune and Glue
      if (eofIndex !== -1) imageBytes = imageBytes.slice(0, eofIndex);

      const obfuscatedPayload = new Uint8Array(result.finalBin);
      // XOR Taint: Reverse-engineered by checkImageForStowaway
      if (obfuscatedPayload.length > 3) {
        obfuscatedPayload[0] = obfuscatedPayload[0] ^ obfuscatedPayload[2];
        obfuscatedPayload[1] = obfuscatedPayload[1] ^ obfuscatedPayload[3];
      }

      finalDownloadData = concatUi8([imageBytes, obfuscatedPayload]);
      fileName = isFolderKey ? `camo_folder_${timestamp}.${extension}` : `camo_note_${timestamp}.${extension}`;
      showStatusMsg(`Note camouflaged in ${extension.toUpperCase()}.`, "good");
    }

    triggerDownload(finalDownloadData, fileName);
    reportCryptoSuccess("encrypt", { mode: isFolderKey ? "FOLDER" : result.modeLabel, recipientCount: state.recipients.length });

    if (mainBox) mainBox.innerHTML = "";
    if (decoyArea) { decoyArea.value = ""; }
    if (typeof startMasterPwdTimeout === "function") startMasterPwdTimeout();

  } catch (err) {
    console.error("Encrypt to File Error:", err);
    showStatusMsg("Encrypt to File Error: " + err.message, "bad");
  }
}

/**
 * Unified Plaintext Structure:
 * [NameLen (1b)] + [Optional Filename] + [Payload Data]
 * If NameLen is 0, it's Box Text (no filename). 
 * If NameLen > 0, it's a File.
 */
function prepareUnifiedPlaintext(dataUint8, fileName = null) {
  if (!fileName) {
    // 0x00: Standard Text/HTML
    const payload = new Uint8Array(1 + dataUint8.length);
    payload[0] = 0;
    payload.set(dataUint8, 1);
    return payload;
  } else if (fileName === "RAW_BINARY") {
    // 0x01: Binary Blob (Folder Keys or Armored Base64)
    const payload = new Uint8Array(1 + dataUint8.length);
    payload[0] = 1;
    payload.set(dataUint8, 1);
    return payload;
  } else {
    // 0x02+: Named Files (Marker is the length of the name)
    const nameBytes = new TextEncoder().encode(fileName);
    const nameLen = Math.min(nameBytes.length, 255);
    const payload = new Uint8Array(1 + nameLen + dataUint8.length);
    payload[0] = nameLen;
    payload.set(nameBytes.subarray(0, nameLen), 1);
    payload.set(dataUint8, 1 + nameLen);
    return payload;
  }
}

async function getUnifiedPayload() {
  const mainBox = document.getElementById('mainBox');
  if (!mainBox) return null;

  // --- CASE A: File Link (Anchor Tag) ---
  const link = mainBox.querySelector('a');
  if (link && (link.href.startsWith('data:') || link.href.startsWith('blob:'))) {
    try {
      const response = await fetch(link.href);
      const fileData = new Uint8Array(await response.arrayBuffer());
      return prepareUnifiedPlaintext(fileData, link.download || "attachment.bin");
    } catch (e) { console.error("Blob fetch failed", e); }
  }

  // --- CASE B: Encrypted/Certified String (Base64) ---
  const rawText = mainBox.innerText || mainBox.textContent;
  const cleanedB64 = cleanBase64(rawText);
  if (cleanedB64.length > 32) {
    try {
      const rawBytes = decodeBase64(cleanedB64);
      return prepareUnifiedPlaintext(rawBytes, "RAW_BINARY");
    } catch (e) { /* Fall through to Text if invalid */ }
  }

  // --- CASE C: Standard Text/HTML ---
  const rawHTML = mainBox.innerHTML.trim();
  if (!rawHTML || rawHTML === "Type or decrypt here..." || rawHTML === "Select an item to view...") {
    return null; // Signals empty box for Folder Key logic
  }
  const compressed = LZString.compressToUint8Array(rawHTML);
  return prepareUnifiedPlaintext(compressed);
}