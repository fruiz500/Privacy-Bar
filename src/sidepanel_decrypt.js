/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

/**
 * Detects the initial marker in a Base64 string.
 */
function getFormat(b64) {
  try {
    const split = b64.split("//////");  //in case there are Locks prepended, we want to ignore them for marker detection
    const blob = split[split.length - 1]; // The last part should be the Base64 blob
    // We only need the first few bytes to check the marker
    const binary = Uint8Array.from(atob(blob.slice(0, 10)), c => c.charCodeAt(0));
    return binary[0];
  } catch (e) {
    return false;
  }
}

// 3. Decrypt Button Listener

async function doDecryptSelection() {
  const box = document.getElementById("mainBox");
  const blobText = box.textContent.trim();

  if (!blobText) {
    showStatusMsg("No encrypted message loaded.", "special");
    return;
  }

  // --- 1. HUMAN MODE DETECTION (Early Exit) ---
  // Strip headers using your == delimiters
  let cleanInput = blobText;
  if (blobText.includes("==")) {
    const parts = blobText.split("==");
    // Take the middle part (the ciphertext)
    cleanInput = parts.length >= 3 ? parts[1] : blobText;
  }

  // Sanitize: remove all spaces/newlines and force Uppercase
  const sanitizedHuman = cleanInput.replace(/\s/g, '').toUpperCase();

  // Detect Human Crypto (Long A-Z sequence)
  const isHumanCrypto = /^[A-Z]{20,}$/.test(sanitizedHuman);

  if (isHumanCrypto) {
    const pwd = prompt("Enter the Human Crypto key (e.g. word1,word2,word3,word4,word5,2):");
    if (!pwd) {
      showStatusMsg("Decryption cancelled.", "bad");
      return;
    }

    const hKey = parseHumanKey(pwd);
    if (hKey) {
      try {
        // Use your existing humanEncryptDecrypt logic
        const decrypted = humanEncryptDecrypt(sanitizedHuman, hKey, false);
        displayResult(decrypted, "HUMAN", "Human Crypto Sender");
        return; // EXIT: Do not proceed to NaCl/Base64 logic
      } catch (e) {
        console.error("Human Crypto error:", e);
        showStatusMsg("Human Crypto decryption failed.", "bad");
        return;
      }
    }
  }

  //marker detection
  const marker = getFormat(cleanInput);

  if (marker === 150) {
    if (typeof startVerification === 'function') return await startVerification();
  }

  // --- 2. STANDARD NACL / BINARY PIPELINE ---
  const masterPwd = document.getElementById("m-pass").value.trim();
  const myEmail = document.getElementById("user-email").value.trim();

  const isStandardMode = !window.activePadBin && !window.activeFolderKey;

  if (isStandardMode && (!masterPwd || !myEmail) && [0, 1, 56, 72, 73].includes(marker)) {
    showStatusMsg("Master Key and Email required.", "special");
    return;
  }
  if (isStandardMode && masterPwd) {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  const cleanForMatching = blobText.replace(/[\s\r\n]/g, '');
  const b64Matches = cleanForMatching.match(/[A-Za-z0-9+/]{50,}/g);

  if (!b64Matches) {
    showStatusMsg("No valid encrypted blob found in the box.", "bad");
    return;
  }

  const rawBlob = b64Matches.reduce((a, b) => a.length > b.length ? a : b);
  const blob = { type: "MESSAGE", raw: rawBlob };

  // 3. Await the result from the pipeline
  const result = await continueDecrypt(blob, masterPwd, myEmail);

  // 4. Update the UI with the decrypted plaintext
  if (result && result.success && result.plaintext) {
    // FIX: Ensure we have a Uint8Array for marker checks and LZString
    const uint8 = (result.plaintext instanceof Blob)
      ? new Uint8Array(await result.plaintext.arrayBuffer())
      : result.plaintext;

    // Check for Folder Key using heuristic tie-breaker
    if (isLikelyFolderKey(uint8)) {
      window.activeFolderKey = uint8;
      displayResult("Folder Key activated", "FOLDER", result.senderName);
      updateFolderKeyUI();
    } else {
      let finalStr = "";
      let workingBuffer = uint8;

      if (workingBuffer[0] === 0) {
        // Path A: Text-to-File (prefixed with 0x00)
        const compressed = workingBuffer.slice(1);
        finalStr = LZString.decompressFromUint8Array(compressed);
      } else {
        // Path C: Standard Text-to-Text Path
        // This is where chat invitations and standard messages land.
        finalStr = LZString.decompressFromUint8Array(workingBuffer);

        if (!finalStr) {
          finalStr = new TextDecoder().decode(workingBuffer);
        }
      }

      if (!finalStr) throw new Error("Decryption yielded empty result.");

      // --- DETECTION: Mirror Mobile App logic ---
      const sanitized = DOMPurify.sanitize(finalStr);

      if (sanitized.startsWith("\x07")) {
        // CHAT INVITE DETECTED: Strip marker and render card
        renderChatInviteCard(sanitized.substring(1));
        return;
      } else if (workingBuffer[0] === 7) {
        // Fallback for uncompressed Chat Invites (New Binary Path)
        renderChatInviteCard(new TextDecoder().decode(workingBuffer.slice(1)));
        return;
      }

      // STANDARD TEXT DISPLAY
      displayResult(sanitized, result.modeLabel || "MESSAGE", result.senderName);
    }
  }
}

/**
 * Distinguishes 32-byte Folder Keys from short messages/files [cite: 2026-04-21].
 */
function isLikelyFolderKey(bin) {
  if (!bin || bin.length !== 32) return false;

  // 1. Try decompression. If it yields a string, it's a message [cite: 2026-04-21].
  try {
    const decompressed = LZString.decompressFromUint8Array(bin);
    if (decompressed && decompressed.length > 0) return false;
  } catch (e) {
    // Decompression failed; might be a key
  }

  // 2. Try UTF-8 decoding. If it's clean printable text, it's a message [cite: 2026-04-21].
  const text = new TextDecoder().decode(bin);
  const printableRegex = /^[\x20-\x7E\s\r\n\t]+$/;
  if (printableRegex.test(text)) return false;

  // 3. High entropy binary with no text/compression structure [cite: 2026-04-21].
  return true;
}

// ==== UNIVERSAL DECRYPTION ====

/**
 * FULL FUNCTION: continueDecrypt
 * Core router for all decryption modes. 
 * Supports chunked Blob processing and legacy Uint8Array text.
 */
async function continueDecrypt(input, masterPwd, myEmail) {
  if (!input) return;

  try {
    let source; // Will be Uint8Array or Blob
    let parsed = { ezLock: null, pqlockBase64: null, ciphertext: "", hasLock: false };

    // 1. EXTRACT LOCKS FIRST (Surgical Extraction)
    // Supports both raw strings (text box) and object inputs
    if (typeof input === 'string' || (input.raw && typeof input.raw === 'string')) {
      const text = input.raw || input.text || input;
      const surgical = extractEmbeddedLock(text);
      parsed.ezLock = surgical.ezLock;
      parsed.pqlockBase64 = surgical.pqlockBase64;
      parsed.hasLock = surgical.hasLock;
      parsed.ciphertext = surgical.ciphertext;

      // IDENTIFY PURE INVITATION (No Ciphertext)
      if (surgical.ezLock && (!surgical.ciphertext || surgical.ciphertext.trim() === "")) {
        await postProcessDecryption(parsed, "INVITATION");
        return {
          success: true,
          plaintext: LZString.compressToUint8Array("Now you can send me encrypted messages by selecting me in the dialog above and using the 'Encrypt' button! First time, make sure you add your Lock by checking the box above."),
          type: "INVITATION",
          modeLabel: "INVITATION"
        };
      }

      // If there IS ciphertext, decode it as usual
      source = decodeBase64(surgical.ciphertext);
    } else {
      // Input is likely already a Uint8Array or Blob (from File handling)
      source = input.raw || input;
    }

    // Validation: Ensure we have enough data to even check a marker
    const sourceSize = (source instanceof Blob) ? source.size : source.length;
    if (!source || sourceSize < 1) throw new Error("Invalid message: Empty source.");

    // 2. PEEK AT MARKER
    const marker = (source instanceof Blob)
      ? new Uint8Array(await source.slice(0, 1).arrayBuffer())[0]
      : source[0];

    // --- SPECIAL BYPASS: MARKER 150 (CERTIFIED) ---
    // Certified messages are verified, not "decrypted" in the standard sense.
    // We route them here to avoid the "Unsupported Mode" error in the standard router.
    if (marker === 150) {
      const fullBin = (source instanceof Blob) ? new Uint8Array(await source.arrayBuffer()) : source;
      const isFromFile = (input instanceof Blob || (input.raw && input.raw instanceof Blob));
      const verifySuccess = await processVerification(fullBin, isFromFile);

      // Return a successful result but signal the UI that it was a verification path
      return {
        success: verifySuccess,
        modeLabel: "CERTIFIED",
        plaintext: null // processVerification handles its own UI injection/download
      };
    }

    // --- STANDARD MARKER TO TYPE MAPPING ---
    let type;
    if (marker === 128) type = "g";            // Folder/Symmetric
    else if (marker === 164) type = "p";       // Pad Mode
    else if (marker === 0) type = "A";         // Anonymous ECC
    else if (marker === 72) type = "S";        // Signed ECC
    else if (marker === 56) type = "O";        // Read Once ECC
    else if (marker === 1) type = "B";         // PQ Anonymous
    else if (marker === 73) type = "T";        // PQ Signed
    else type = String.fromCharCode(marker);

    // 3. COMMON DATA DERIVATION
    // MP/Email are only strictly required for identity-dependent modes (0, 1, 56, 72, 73)
    const commonData = [0, 1, 56, 72, 73].includes(marker)
      ? await prepareCommonData(masterPwd, myEmail)
      : null;

    // 4. ROUTE BY MODE
    // The handlers are now updated to return the Key and the payloadOffset (chunk start)
    const result = await routeByMode(type, source, parsed, commonData);

    if (!result.success) throw new Error(result.error);

    // 5. DECRYPT THE PAYLOAD
    let finalPlaintext;
    if (result.plaintext) {
      // Pad Mode or Human mode directly returns the plaintext/message
      finalPlaintext = result.plaintext;
    } else {
      // Standard flow: Invoke the Chunked Decryption Engine
      // This handles incrementing nonces and streaming decryption
      finalPlaintext = await decryptPayload(source, result.payloadOffset, result.nonce, result.msgKey);
    }

    // 6. CLEANUP & METADATA
    await postProcessDecryption(parsed, type);

    // Preserve the padding for possible Decoy Decryption (Step 10)
    window.lastDecryptedPadding = result.padding;

    // Return the unified result object to doDecryptSelection or processFileDecryption
    return {
      success: true,
      plaintext: finalPlaintext,
      type: type,
      modeLabel: result.modeLabel,
      senderName: result.senderName
    };

  } catch (e) {
    console.error("Decryption error:", e);
    showStatusMsg(e.message, "bad");
    return { success: false, error: e.message };
  }
}

async function routeByMode(type, cipherText, parsed, commonData) {
  switch (type) {
    case "g": return handleGMode(cipherText, parsed);
    case "B": return handlePQAnonymousMode(cipherText, commonData); // Marker 1
    case "T": return handlePQSignedMode(cipherText, parsed, commonData); // Marker 73
    case "A": return handleAnonymousMode(cipherText, commonData);
    case "S": return handleSignedMode(cipherText, parsed, commonData);
    case "O": return handleOnceMode(cipherText, parsed, commonData);
    case "l": return startVerification();
    case "p": return handlePadMode(cipherText);
    default: return { success: false, error: `Unsupported mode: ${type}` };
  }
}

//decrypt pad mode messages
async function handlePadMode(input) {
  try {
    const isBlob = (input instanceof Blob);
    const header = isBlob
      ? new Uint8Array(await input.slice(0, 116).arrayBuffer())
      : input.slice(0, 116);

    if (header[0] !== 164) throw new Error("Invalid Pad mode marker");
    const nonce15 = header.slice(1, 16);
    const padding = header.slice(16, 116);

    if (!window.activePadBin) throw new Error("Pad file missing.");
    const pad = window.activePadBin;

    const seedInput = concatUi8([nonce15, pad]);
    const seedHash = await sha512Uint8(seedInput);
    let start64 = 0n;
    for (let i = 0; i < 8; i++) start64 = (start64 << 8n) | BigInt(seedHash[i]);
    const startIndex = Number(start64 % BigInt(pad.length || 1));

    let padCursor = startIndex;
    const { chunk: hmacPadChunk, nextIndex: hmacNextIndex } = await findPadChunk(pad, padCursor, 512, { step: 64 });
    const hmacKeyRaw = await sha512Uint8(hmacPadChunk);
    const hmacKey = await crypto.subtle.importKey("raw", hmacKeyRaw, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
    padCursor = hmacNextIndex;

    const results = [];
    const FILE_CHUNK = 64 * 1024;
    const HMAC_SIZE = 32;
    let currentPos = 116; // FIXED: Sync with 116-byte header
    const totalSize = isBlob ? input.size : input.length;

    while (currentPos < totalSize) {
      const remaining = totalSize - currentPos;
      const isLast = remaining <= (FILE_CHUNK + HMAC_SIZE);
      const cipherSize = isLast ? (remaining - HMAC_SIZE) : FILE_CHUNK;

      const segment = isBlob
        ? new Uint8Array(await input.slice(currentPos, currentPos + cipherSize + HMAC_SIZE).arrayBuffer())
        : input.slice(currentPos, currentPos + cipherSize + HMAC_SIZE);

      if (segment.length < HMAC_SIZE) break;
      const cipherChunk = segment.slice(0, cipherSize);
      const receivedMac = segment.slice(cipherSize);

      const fullMac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, cipherChunk));
      if (!u8Equals(fullMac.slice(0, 32), receivedMac)) throw new Error("Integrity failure.");

      const plainChunk = new Uint8Array(cipherSize);
      for (let offset = 0; offset < cipherSize; offset += 64) {
        const subSize = Math.min(64, cipherSize - offset);
        const { chunk: padChunk, nextIndex } = await findPadChunk(pad, padCursor, 512, { step: 64 });
        const keyMaterial = await sha512Uint8(padChunk);
        for (let j = 0; j < subSize; j++) plainChunk[offset + j] = cipherChunk[offset + j] ^ keyMaterial[j];
        padCursor = nextIndex;
      }
      results.push(plainChunk);
      currentPos += (cipherSize + HMAC_SIZE);
    }

    // Return RAW decrypted stream to let processFileDecryption handle metadata stripping
    return {
      success: true,
      plaintext: isBlob ? new Blob(results) : concatUi8(results),
      senderName: "Pad File",
      modeLabel: "PAD",
      padding: padding
    };
  } catch (e) {
    console.error("Pad Decryption Error:", e);
    return { success: false, error: e.message };
  }
}

//symmetric decryption
async function handleGMode(input, parsed) {
  try {
    // 1. Get header bytes (164 bytes)
    const headerBytes = (input instanceof Blob)
      ? new Uint8Array(await input.slice(0, 164).arrayBuffer())
      : input.slice(0, 164);

    if (headerBytes[0] !== 128) throw new Error("Invalid g-mode marker");

    const nonce15 = headerBytes.slice(1, 16);
    const padding = headerBytes.slice(16, 116);
    const sessionKeySlot = headerBytes.slice(116, 164);
    const nonce24 = makeNonce24(nonce15);

    let msgKey = null;
    let isInvitation = false;

    if (parsed?.ezLock) {
      const opened = nacl.secretbox.open(sessionKeySlot, nonce24, decodeBase36ToUint8(parsed.ezLock));
      if (opened) { msgKey = opened; isInvitation = true; }
    }

    if (!msgKey && window.activeFolderKey) {
      const opened = nacl.secretbox.open(sessionKeySlot, nonce24, window.activeFolderKey);
      if (opened) msgKey = opened;
    }

    if (!msgKey) {
      const pwd = prompt("Enter Shared Key for Symmetric message:");
      if (pwd) {
        showStatusMsg('<span class="pb-stretching">Stretching Master Key...</span>', 'info');
        await new Promise(r => setTimeout(r, 50));

        const symKey = wiseHash(pwd, encodeBase64(nonce15));
        const opened = nacl.secretbox.open(sessionKeySlot, nonce24, symKey);
        if (opened) msgKey = opened;
      }
    }

    if (!msgKey) throw new Error("Decryption failed. Invalid Lock or Shared Key.");

    return {
      success: true,
      msgKey: msgKey,
      nonce: nonce24,
      padding: padding,
      payloadOffset: 164, // Explicit offset for chunking
      modeLabel: isInvitation ? "INVITATION" : "SYMMETRIC",
      isInvitation: isInvitation
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

//anonymous mode
async function handleAnonymousMode(cipherInput, commonData) {
  try {
    const { myKey, myLockbin } = commonData;

    // --- CHUNKED PEEK ---
    // Extract components from binary (Header is 149 bytes)
    const header = (cipherInput instanceof Blob)
      ? new Uint8Array(await cipherInput.slice(0, 149).arrayBuffer())
      : cipherInput.slice(0, 149);

    const recipients = header[1];
    const nonce = header.slice(2, 17); // 15 bytes
    const padding = header.slice(17, 117); // 100 bytes
    const pubdum = header.slice(117, 149); // 32 bytes

    const sharedKey = makeShared(pubdum, myKey);
    const nonce24 = makeNonce24(nonce);
    const stuffForId = myLockbin;
    const idTag = nacl.secretbox(stuffForId, nonce24, sharedKey).slice(0, 8);

    // --- SLOT PROBING ---
    const slotSize = 56;
    const headerOffset = 149;
    const totalSlotsSize = slotSize * recipients;

    const cipherData = (cipherInput instanceof Blob)
      ? new Uint8Array(await cipherInput.slice(headerOffset, headerOffset + totalSlotsSize).arrayBuffer())
      : cipherInput.slice(headerOffset, headerOffset + totalSlotsSize);

    const matchedSlot = findEncryptedMessageKey(recipients, cipherData, idTag, slotSize);
    if (!matchedSlot) throw new Error("This message was not encrypted for you");

    const msgKeycipher = matchedSlot.slotData;
    const msgKey = nacl.secretbox.open(msgKeycipher, nonce24, sharedKey);
    if (!msgKey) throw new Error("Failed to decrypt message key");

    return {
      success: true,
      msgKey: msgKey,
      nonce: nonce24,
      padding: padding,
      payloadOffset: headerOffset + totalSlotsSize, // Updated for chunking
      modeLabel: "MESSAGE",
      senderName: "Anonymous"
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

//signed mode
async function handleSignedMode(cipherInput, parsed, commonData) {
  try {
    const { myKey, myLockbin, base36Lock } = commonData;

    // --- CHUNKED PEEK (Header is 117 bytes) ---
    const header = (cipherInput instanceof Blob)
      ? new Uint8Array(await cipherInput.slice(0, 117).arrayBuffer())
      : cipherInput.slice(0, 117);

    const recipients = header[1];
    const nonce = header.slice(2, 17);
    const padding = header.slice(17, 117);
    const nonce24 = makeNonce24(nonce);
    const stuffForId = myLockbin;

    const slotSize = 56;
    const headerOffset = 117;
    const totalSlotsSize = slotSize * recipients;

    const cipherData = (cipherInput instanceof Blob)
      ? new Uint8Array(await cipherInput.slice(headerOffset, headerOffset + totalSlotsSize).arrayBuffer())
      : cipherInput.slice(headerOffset, headerOffset + totalSlotsSize);

    // 1. If prepended Lock, try to decrypt with it
    if (parsed.hasLock) {
      const senderLock = decodeBase36ToUint8(parsed.ezLock);
      if (senderLock) {
        const sharedKey = makeShared(ed2curve.convertPublicKey(senderLock), myKey);
        const idTag = nacl.secretbox(stuffForId, nonce24, sharedKey).slice(0, 8);
        const matchedSlot = findEncryptedMessageKey(recipients, cipherData, idTag, slotSize, parsed.ezLock, base36Lock);
        if (matchedSlot) {
          const msgKeycipher = matchedSlot.slotData;
          const msgKey = nacl.secretbox.open(msgKeycipher, nonce24, sharedKey);
          if (msgKey) {
            return {
              success: true,
              msgKey: msgKey,
              nonce: nonce24,
              padding: padding,
              payloadOffset: headerOffset + totalSlotsSize,
              senderName: matchedSlot.senderName
            };
          }
        }
      }
    }

    // 2. Fallback: Try site-specific lock and all known Locks in locDir
    const host = currentHost;
    const storageKeys = ['locDir'];
    if (host) storageKeys.push(host);

    const storageData = await chrome.storage.sync.get(storageKeys);
    const locDir = storageData.locDir || {};

    let locksToTry = [];
    if (host && storageData[host] && storageData[host].crypt && storageData[host].crypt.lock) {
      locksToTry.push({ name: "Me", lockStr: storageData[host].crypt.lock });
    }
    for (const [name, data] of Object.entries(locDir)) {
      locksToTry.push({ name: name, lockStr: data.lock });
    }

    for (const entry of locksToTry) {
      try {
        const senderLock = decodeBase36ToUint8(entry.lockStr);
        if (!senderLock) continue;

        const sharedKey = makeShared(ed2curve.convertPublicKey(senderLock), myKey);
        const idTag = nacl.secretbox(stuffForId, nonce24, sharedKey).slice(0, 8);

        const matchedSlot = findEncryptedMessageKey(recipients, cipherData, idTag, slotSize, entry.lockStr, base36Lock);
        if (!matchedSlot) throw new Error("ID mismatch");

        const msgKeycipher = matchedSlot.slotData;
        if (msgKeycipher) {
          const msgKey = nacl.secretbox.open(msgKeycipher, nonce24, sharedKey);
          if (msgKey) {
            return {
              success: true,
              msgKey: msgKey,
              nonce: nonce24,
              padding: padding,
              payloadOffset: headerOffset + totalSlotsSize,
              senderName: entry.name,
              modeLabel: "SIGNED"
            };
          }
        }
      } catch (e) { continue; }
    }

    throw new Error("This message was not encrypted for you");
  } catch (e) {
    return { success: false, error: e.message };
  }
}

function findNameByLock(ezLockToFind) {
  // Reference the global locDir
  for (const [name, data] of Object.entries(locDir)) {
    if (data.lock === ezLockToFind) {
      return name; // Return the name (email/key) if lock matches
    }
  }
  return null; // Return null if no match is found
}

function getStoredEphemeralKey(recipientName) {
  // Reference the global locDir
  const entry = locDir[recipientName];

  if (entry && entry.ro && entry.ro.lastkey) {
    return entry.ro.lastkey; // Return the stored ephemeral key cipher
  }

  return null; // Return null if not found or not set
}

/**
 * Handles decryption for Read once mode ("O").
 * Tries direct sender lookup via ezLock, then falls back to trying all known senders.
 *
 * @param {Uint8Array} cipherText - The full decoded ciphertext.
 * @param {Object} parsed - The result from extractEmbeddedLock (hasLock, ezLock, etc.).
 * @param {Object} commonData - Data from prepareCommonData (myKey, myLockbin, etc.).
 * @returns {Promise<{ success: boolean, msgKey?: Uint8Array, theirEmail?: string, error?: string }>}
 */
async function handleOnceMode(cipherInput, parsed, commonData) {
  try {
    const { myKey, myLockbin, storageKey, base36Lock } = commonData;

    // 1. Structural Constants for Mode 56 ("O")
    const headerOffset = 117;
    const slotSize = 105;

    // 2. Peek at the Header (117 bytes)
    const head = (cipherInput instanceof Blob)
      ? new Uint8Array(await cipherInput.slice(0, headerOffset).arrayBuffer())
      : cipherInput.slice(0, headerOffset);

    const recipients = head[1];
    const nonce15 = head.slice(2, 17);
    const nonce24 = makeNonce24(nonce15);
    const padding = head.slice(17, 117);
    const stuffForId = myLockbin;

    // 3. Extract all Recipient Slots
    const totalSlotsSize = slotSize * recipients;
    const slotsBytes = (cipherInput instanceof Blob)
      ? new Uint8Array(await cipherInput.slice(headerOffset, headerOffset + totalSlotsSize).arrayBuffer())
      : cipherInput.slice(headerOffset, headerOffset + totalSlotsSize);

    /**
     * Helper for finding/decrypting a candidate inside the loop
     * Preserves the "Double-Pass" logic: 1. Ephemeral 2. Permanent Fallback
     */
    const tryCandidate = async (email, lockStr, lastKeyCipher) => {
      const senderLock = decodeBase36ToUint8(lockStr);
      if (!senderLock) return null;

      const recipientPub = ed2curve.convertPublicKey(senderLock);

      // PASS 1: Try with Ephemeral Key (Normal flow)
      if (lastKeyCipher) {
        const lastKey = keyDecrypt(lastKeyCipher, storageKey, true);
        if (lastKey) {
          const idKey = nacl.box.before(recipientPub, lastKey);
          const idTag = nacl.secretbox(stuffForId, nonce24, idKey).slice(0, 8);
          const matchedSlot = findEncryptedMessageKey(recipients, slotsBytes, idTag, slotSize, lockStr, base36Lock);
          if (matchedSlot) {
            const res = await tryReadOnceDecrypt(email, matchedSlot.slotData, idKey, nonce24, padding, null, commonData);
            if (res.success) return res;
          }
        }
      }

      // PASS 2: Try with Permanent Key (Reset/PFS fallback)
      const idKeyPerm = nacl.box.before(recipientPub, myKey);
      const idTagPerm = nacl.secretbox(stuffForId, nonce24, idKeyPerm).slice(0, 8);
      const matchedSlotPerm = findEncryptedMessageKey(recipients, slotsBytes, idTagPerm, slotSize, lockStr, base36Lock);
      if (matchedSlotPerm) {
        const res = await tryReadOnceDecrypt(email, matchedSlotPerm.slotData, idKeyPerm, nonce24, padding, null, commonData);
        if (res.success) return res;
      }
      return null;
    };

    // 4. EXECUTION: Prioritize the prepended Lock
    if (parsed.hasLock) {
      const email = findNameByLock(parsed.ezLock) || "Unknown Sender";
      const result = await tryCandidate(email, parsed.ezLock, getStoredEphemeralKey(email));
      if (result) {
        result.payloadOffset = headerOffset + totalSlotsSize;
        return result;
      }
    }

    // 5. FALLBACK: Loop through all candidates in locDir
    for (const [email, data] of Object.entries(window.locDir)) {
      if (email === 'myself' || !data.lock) continue;
      const result = await tryCandidate(email, data.lock, data.ro?.lastkey);
      if (result) {
        result.payloadOffset = headerOffset + totalSlotsSize;
        return result;
      }
    }

    throw new Error("Read once error: No matching sender or already read.");
  } catch (e) {
    return { success: false, error: e.message };
  }
}

/**
 * Core decryption logic for a single potential sender.
 * This is the heart of the Read once decryption process.
 *
 * @param {string} theirEmail - The email of the potential sender.
 * @param {string} theirLockB64 - The Base64 encoded lock of the potential sender.
 * @param {Object} parsed - Data from parseHeader.
 * @param {Object} commonData - Data from prepareCommonData.
 * @returns {Promise<{ success: boolean, msgKey?: Uint8Array, theirEmail?: string, error?: string }>}
 */
async function tryReadOnceDecrypt(senderName, matchedData, idKey, nonce24, padding, cipher_Legacy_Ignore, commonData) {
  const { myKey, storageKey } = commonData;

  // slotSize (105) - idTag (8) = 97 bytes
  if (matchedData.length !== 97) {
    return { success: false, error: "Invalid Read once slot size." };
  }

  const cipher2 = matchedData.slice(0, 48);
  const typeByte = matchedData[48];
  const newLockCipher = matchedData.slice(49, 97);

  // --- REVISED INITIALIZATION ---
  let entry = window.locDir[senderName];
  if (!entry) {
    // If recipient is totally new, create entry with RO object
    entry = { ro: {} };
    window.locDir[senderName] = entry;
  } else if (!entry.ro) {
    // If recipient exists (from standard modes) but hasn't used RO, add the RO object
    entry.ro = {};
  }

  const lastKeyCipher = entry.ro.lastkey;
  const lastLockCipher = entry.ro.lastlock;

  const newLockBin = nacl.secretbox.open(newLockCipher, nonce24, idKey);
  if (!newLockBin) return { success: false, error: "Read-once: Failed to decrypt sender's new lock." };

  let sharedKey;
  const typeValue = typeByte[0] || typeByte;

  if (typeValue === 172) { // RESET (Marker 172)
    const agree = confirm(`If you proceed, the current Read-once conversation with ${senderName} will be reset.`);
    if (!agree) return { success: false, error: "User aborted reset." };
    sharedKey = nacl.box.before(newLockBin, myKey);
    entry.ro.lastkey = null;
    entry.ro.lastlock = null;
  }
  else if (typeValue === 164) { // PFS / Unlock re-send (Marker 164)
    const lastKey = lastKeyCipher ? keyDecrypt(lastKeyCipher, storageKey, true) : myKey;
    sharedKey = nacl.box.before(newLockBin, lastKey);
  }
  else { // NORMAL (Marker 160)
    const lastKey = lastKeyCipher ? keyDecrypt(lastKeyCipher, storageKey, true) : null;
    if (!lastKey) return { success: false, error: "Sync error: Missing ephemeral key." };
    
    // CRITICAL: We MUST have a stored lock. No fallback to newLockBin.
    const lastLock = lastLockCipher ? keyDecrypt(lastLockCipher, storageKey, true) : null;
    if (!lastLock) return { success: false, error: "Sync error: Missing ephemeral lock." };
    
    sharedKey = nacl.box.before(lastLock, lastKey);
  }

  const msgKey = nacl.secretbox.open(cipher2, nonce24, sharedKey);
  if (!msgKey) return { success: false, error: "Read-once: Key mismatch (Message already read or sync error)." };

  // --- ENFORCE ONCE-ONLY ---
  // Overwrite the previous lock with the one sent in this message.
  // This invalidates the current ciphertext for any future decryption attempts.
  entry.ro.lastlock = keyEncrypt(newLockBin, storageKey);
  
  // Transition Bob to 'lock' so he is ready to reply.
  entry.ro.turn = 'lock';

  window.locDir[senderName] = entry;

  // Guard against undefined references before syncing
  if (typeof syncLocDir === 'function') {
    await syncLocDir(window.locDir);
  }

  return {
    success: true,
    msgKey,
    nonce: nonce24,
    padding,
    senderName,
    modeLabel: "READ ONCE"
  };
}

// Centralized decryption function for the actual message payload, used by all modes after obtaining the message key.
/**
 * Synchronized with the encryption sequence-nonce logic (Offset 20).
 */
async function decryptPayload(source, offset, baseNonce, msgKey) {
  const CT_CHUNK = (64 * 1024) + 16; // 64kB + 16-byte Poly1305 tag
  const results = [];
  let currentPos = offset;
  let chunkIdx = 0;

  const totalSize = (source instanceof Blob) ? source.size : source.length;

  while (currentPos < totalSize) {
    // Provide UI feedback every 20 chunks (~1.2MB)
    if (chunkIdx % 20 === 0 && totalSize > CT_CHUNK * 5) {
      showStatusMsg(`Decrypting: ${Math.round((currentPos / totalSize) * 100)}%`, "info");
    }
    const slice = (source instanceof Blob)
      ? new Uint8Array(await source.slice(currentPos, currentPos + CT_CHUNK).arrayBuffer())
      : source.slice(currentPos, Math.min(currentPos + CT_CHUNK, totalSize));

    if (slice.length === 0) break;

    // FIX: Match the encryption nonce increment at byte 20
    const currentNonce = new Uint8Array(baseNonce);
    new DataView(currentNonce.buffer).setUint32(20, chunkIdx, false);

    const decrypted = nacl.secretbox.open(slice, currentNonce, msgKey);
    if (!decrypted) throw new Error(`Integrity failure at segment ${chunkIdx}.`);

    results.push(decrypted);
    currentPos += CT_CHUNK;
    chunkIdx++;
  }

  return (source instanceof Blob) ? new Blob(results) : concatUi8(results);
}

async function postProcessDecryption(parsed, type) {
  // Instead of auto-saving, prompt user if Lock is new
  if (/[gASOBTp]/.test(type)) {
    await promptUserToNameSenderLock(parsed);
  }
}

async function promptUserToNameSenderLock(parsed) {
  // Ensure we use the exact names from the embedded parser
  const theirLockB36 = parsed.ezLock;
  const theirpqlockBase64 = parsed.pqlockBase64;

  if (!theirLockB36) return;

  // 1. SELF-RECOGNITION GATE
  // Using global currentHost and sync storage per project configuration
  if (typeof currentHost !== 'undefined' && currentHost) {
    const syncData = await chrome.storage.sync.get(currentHost);
    const mySiteIdentity = syncData[currentHost]?.crypt?.lock;

    if (mySiteIdentity === theirLockB36) {
      console.log("Sender verified as 'Me'. Skipping directory prompt.");
      return;
    }
  }

  // 2. DIRECTORY CHECK
  const data = await chrome.storage.sync.get(['locDir']);
  const locDir = data.locDir || {};

  // Find if this specific lock already exists in our directory
  const knownEntry = Object.entries(locDir).find(([_, entry]) => entry.lock === theirLockB36);

  if (knownEntry) {
    const [name, entry] = knownEntry;

    // UPGRADE CASE
    if (theirpqlockBase64 && !entry.pqlock) {
      entry.pqlock = theirpqlockBase64;

      // Generate the hash for the "Manage" view
      if (typeof makePQPrint === 'function') {
        const identity = makePQPrint(entry.pqlock);
        entry.hash = identity.hashBase36;
      }

      await syncLocDir(locDir);
      if (typeof showStatusMsg === 'function') {
        showStatusMsg(`${name} upgraded to Post-Quantum`, "good");
      }
    }
  } else {
    // NEW SENDER CASE (Limited for Free Users)
    const isPro = window.PB_PRO_STATUS && window.PB_PRO_STATUS.active;

    if (!isPro && Object.keys(locDir).length >= 10) {
      if (typeof window.checkProGate === 'function') window.checkProGate();
      return;
    }

    // Only prompt for a name if they are under the limit or Pro
    if (typeof promptForSenderName === 'function') {
      await promptForSenderName(theirLockB36, theirpqlockBase64);
    }
  }
}

/**
 * Finds the encrypted message key chunk for a given recipient based on ID tag.
 * @param {number} recipients - Number of recipient slots.
 * @param {Uint8Array} cipherInput - The raw cipher data containing all recipient chunks.
 * @param {Uint8Array} idTag - The 8-byte ID tag to match.
 * @param {number} [slotSize=56] - The size of each recipient chunk in bytes. Defaults to 56 for Signed mode.
 * @returns {Uint8Array|null} The matching chunk (without the ID tag) or null if not found.
 */
function findEncryptedMessageKey(recipients, cipherInput, idTag, slotSize = 56, senderEzLock = null, meLock = null) {
  // Iterate directly through the cipherInput buffer in slotSize chunks
  for (let i = 0; i < recipients; i++) {
    const slotStart = slotSize * i;
    const slotEnd = slotStart + slotSize;

    // Safety check to prevent reading past the buffer
    if (slotEnd > cipherInput.length) {
      console.warn(`Slot ${i} exceeds cipherInput bounds. Skipping.`);
      continue;
    }

    // Extract the 8-byte ID tag from the start of this chunk
    let match = true;
    for (let j = 0; j < 8; j++) {
      if (idTag[j] !== cipherInput[slotStart + j]) {
        match = false;
        break;
      }
    }

    // If ID tag matches, return the rest of the chunk and the sender's name
    if (match) {
      const slotData = cipherInput.slice(slotStart + 8, slotEnd);

      let senderName = senderEzLock || "Unknown Sender";

      if (senderEzLock) {
        // Priority Check: Is the sender actually 'Me'? [cite: 2026-04-24]
        if (meLock && senderEzLock === meLock) {
          senderName = "Me";
        } else {
          // 3. Fallback: Search the global contact directory
          for (const [name, data] of Object.entries(locDir)) {
            if (data.lock === senderEzLock) {
              senderName = name;
              break;
            }
          }
        }
      }

      return {
        slotData: slotData,
        senderName: senderName
      };
    }
  }

  // No matching recipient slot found
  return null;
}

/**
 * Displays decrypted plaintext and updates status with sender info if available.
 */

function displayResult(content, modeLabel, senderName) {
  const box = document.getElementById('mainBox');
  if (!box) return;

  let displayHeader = "";
  if (modeLabel === "INVITATION") {
    displayHeader = `<div style="background: #fff8e1; border: 1px solid #ffe082; padding: 10px; margin-bottom: 10px; border-radius: 4px; font-size: 13px;">
      <strong>Invitation Accepted:</strong> Please provide a name for this sender if a dialogue pops above, to save their Lock to your directory.
    </div>`;
  }

  box.innerHTML = displayHeader + DOMPurify.sanitize(content);
  setCryptoMode("decrypt");

  // Show the indicator if a Folder Key was just activated
  if (modeLabel === "FOLDER") {
    const folderIndicator = document.getElementById('folder-active-indicator');
    if (folderIndicator) folderIndicator.style.display = 'block';
  }
  // Note: We do NOT hide it here for other modes, because the key 
  // is still in memory and still overriding standard logic.

  reportCryptoSuccess("decrypt", {
    type: modeLabel,
    length: content.length,
    senderLock: senderName
  });

  box.focus();
}

// 3. The Prompt Function
let pendingIdentity = { lock: null, pqlock: null }; // Replaces your single pendingLock variable

async function promptForSenderName(theirLockB36, theirpqlockBase64) {
  // 1. Ask the user who this is
  const name = prompt("New sender detected. Enter a name to save this identity:");
  if (!name || name.trim() === "") {
    showStatusMsg("Identity not saved.", "info");
    return;
  }

  const cleanName = name.trim();
  const data = await chrome.storage.sync.get(['locDir']);
  const locDir = data.locDir || {};

  // 2. Generate the Hybrid Identity (Visual Hash & Metadata)
  const identity = makePQPrint(theirpqlockBase64);

  // 3. Create the Entry
  locDir[cleanName] = {
    lock: theirLockB36,
    pqlock: theirpqlockBase64 || null, // Store as Base-188
    hash: identity.hashBase36      // The fingerprint
  };

  // 4. Save to Storage
  await syncLocDir(locDir);
  showStatusMsg(`Saved ${cleanName} to directory with PQ support.`, "good");

  // Refresh the UI lock list if applicable
  if (typeof updateLockList === 'function') updateLockList();
}

// 2. The Save Button Listener
function saveSenderLock() {
  const nameInput = document.getElementById("new-sender-name");
  const name = nameInput.value.trim();
  if (!name) {
    showStatusMsg("Please enter a name.", "special");
    return;
  }

  chrome.storage.sync.get(["locDir"], (result) => {
    let locDir = result.locDir || {};

    // Use the multi-part identity if available, otherwise fallback to the single pendingLock
    const lockB36 = (typeof pendingIdentity !== 'undefined' && pendingIdentity.lock) ? pendingIdentity.lock : pendingLock;
    const pqlockBase64 = (typeof pendingIdentity !== 'undefined' && pendingIdentity.pqlock) ? pendingIdentity.pqlock : null;

    // Generate the PQ fingerprint
    const identity = makePQPrint(pqlockBase64);

    // Initialize or Update the entry
    if (typeof locDir[name] !== 'object' || locDir[name] === null || Array.isArray(locDir[name])) {
      locDir[name] = {};
    }

    locDir[name].lock = lockB36;
    locDir[name].pqlock = pqlockBase64;
    locDir[name].hash = identity.hashBase36; // Stored for fast Step 7 matching

    chrome.storage.sync.set({ locDir }, () => {
      document.getElementById("sender-prompt-overlay").classList.add("hidden");
      nameInput.value = "";
      window.locDir = locDir;

      if (typeof renderDirectory === 'function') {
        lastRenderTime = 0;
        renderDirectory();
      }
      if (typeof window.updateLockList === 'function') {
        window.updateLockList();
      }

      showStatusMsg(`Sender "${name}" saved with Hybrid Identity.`, "good");

      // Cleanup globals
      pendingLock = null;
      if (typeof pendingIdentity !== 'undefined') pendingIdentity = { lock: null, pqlock: null };
    });
  });
}

// 1. New Validation Function
async function validateAndUpdateMeLock(email, generatedLock, host, generatedpqlock) {
  if (!email || !generatedLock || !host) return true;

  const data = await chrome.storage.sync.get([host]);
  const hostData = data[host] || {};
  const crypt = hostData.crypt || {};
  const existingLock = crypt.lock || null;

  // 1. SUCCESS: The password matches the existing identity.
  // We save the generatedpqlock silently to "backfill" it if it's missing.
  if (!existingLock || existingLock === generatedLock) {
    crypt.lock = generatedLock;
    crypt.pqlock = generatedpqlock;
    crypt.email = email;
    hostData.crypt = crypt;
    await chrome.storage.sync.set({ [host]: hostData });
    return true;
  }

  // 2. MISMATCH: The password produces a different Classic Lock.
  const confirmUpdate = confirm(
    `The Lock generated from your Master Key does not match the stored Lock for (Me) ${email}.\n\nUpdate your identity locks to match your current Master Key?`
  );

  if (confirmUpdate) {
    crypt.lock = generatedLock;
    crypt.pqlock = generatedpqlock; // Update both together
    crypt.email = email;
    hostData.crypt = crypt;
    await chrome.storage.sync.set({ [host]: hostData });
    return true;
  }

  // User declined the update; the MP was likely wrong for this specific identity.
  return false;
}

async function doDecoyDecrypt() {
  //pro feature
  if (!window.checkProGate()) return;

  // 1. Hide the button immediately to prevent double-clicks
  const section = document.getElementById('decoy-decrypt-section');
  if (section) section.style.display = 'none';

  const padding = window.lastDecryptedPadding;
  if (!padding) return;

  const decoyKeyStr = prompt("Enter the secret key for the hidden message:");
  if (!decoyKeyStr) {
    return;
  } else {
    showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
    await new Promise(r => setTimeout(r, 50));
  }

  try {
    const nonce = padding.slice(0, 9);
    const cipherMsg = padding.slice(9);
    const nonce24 = makeNonce24(nonce);

    // The 'work' happens here
    const sharedKey = wiseHash(decoyKeyStr, encodeBase64(nonce));
    const plain = nacl.secretbox.open(cipherMsg, nonce24, sharedKey);

    if (plain) {
      const decoded = decodeURI(new TextDecoder().decode(plain)).trim();
      const readMsg = document.getElementById('mainBox');

      // Append the hidden message to the display
      const hiddenDiv = document.createElement('div');
      hiddenDiv.style.marginTop = "10px";
      hiddenDiv.style.padding = "8px";
      hiddenDiv.style.borderLeft = "4px solid #607d8b";
      hiddenDiv.style.backgroundColor = "#f1f1f1";
      hiddenDiv.innerHTML = "<strong>Hidden Message:</strong><br>" + DOMPurify.sanitize(decoded);

      readMsg.appendChild(hiddenDiv);

      // Clean up

      window.lastDecryptedPadding = null;
    } else {
      showStatusMsg("No hidden message found.", "info");
    }
  } catch (err) {
    console.error("Decoy Decryption Error:", err);
    showStatusMsg("Error attempting decoy decryption.", "bad");
  }
}

// Entry point for file decryption
async function startDecryption(fileBytes) {
  const masterPwdField = document.getElementById('m-pass');

  // 1. Store the bytes globally
  window.pendingFileBytes = fileBytes;

  // 2. Set the context so the Enter key knows what to do
  window.masterPasswordContext = "decrypt";

  const isStandardMode = !window.activePadBin && !window.activeFolderKey;

  // 3. If password is ready, just click the button for the user
  if (masterPwdField?.value || !isStandardMode) {
    document.getElementById("do-decrypt-selection").click();
  } else {
    // 4. Otherwise, prompt and focus
    showStatusMsg("Enter Master Key to decrypt file.", "special");
    masterPwdField?.focus();
  }
}

/**
 * Helper to actually run the decryption once we have bytes and password
 */
async function proceedWithFileDecryption(fileBytes, masterPwd) {
  const storage = await chrome.storage.sync.get([currentHost]);
  const myEmail = storage[currentHost]?.crypt?.email || "";

  const blob = {
    raw: fileBytes,
    base64: encodeBase64(fileBytes)
  };

  await continueDecrypt(blob, masterPwd, myEmail);
  window.pendingFileBytes = null; // Clear after success
}

/**
 * Unified Decryption Bridge for Files.
 * Mirrors prepareUnifiedPlaintext by checking the first byte [0/Len].
 * Standardized to handle the [NameLen][Name][Data] metadata structure.
 */
async function processFileDecryption(fileBlob, outName) {
  try {
    const masterPwd = document.getElementById("m-pass").value.trim();
    const myEmail = document.getElementById("user-email").value.trim();

    if (masterPwd) {
      showStatusMsg('<span class="pb-stretching">Stretching Key...</span>', 'info');
      await new Promise(r => setTimeout(r, 50));
    }

    // 1. Core Decryption Step
    // Normalize input: Ensure continueDecrypt receives a Blob even if called from Stego logic
    const inputBlob = (fileBlob instanceof Uint8Array) ? new Blob([fileBlob]) : fileBlob;
    const result = await continueDecrypt(inputBlob, masterPwd, myEmail);
    if (!result || !result.success) return false;

    // 2. Normalize Output: Ensure decryptedBlob is a Blob to support .arrayBuffer()
    const decryptedBlob = (result.plaintext instanceof Uint8Array) 
      ? new Blob([result.plaintext]) 
      : result.plaintext;

    const peekBuf = new Uint8Array(await decryptedBlob.slice(0, 300).arrayBuffer());

    // 3. Folder Key Detection
    if (decryptedBlob.size === 32 && isLikelyFolderKey(peekBuf.subarray(0, 32))) {
      window.activeFolderKey = peekBuf.subarray(0, 32);
      const indicator = document.getElementById('folder-active-indicator');
      if (indicator) indicator.style.display = 'block';
      showStatusMsg("Folder Key detected and activated.", "good");
      return true;
    }

    // 4. Metadata Parsing
    const nameLen = peekBuf[0];

    if (nameLen === 0) {
      // CASE: Text-to-File (Marker 0 + Compressed HTML)
      const compressedPayload = new Uint8Array(await decryptedBlob.slice(1).arrayBuffer());
      const html = LZString.decompressFromUint8Array(compressedPayload);

      if (html) {
        document.getElementById('mainBox').innerHTML = DOMPurify.sanitize(html);
        setCryptoMode("decrypt");
        showStatusMsg(`Decrypted message from ${result.senderName || 'Sender'}`, "good");
      } else {
        triggerDownload(new Blob([compressedPayload]), outName);
      }
    } else {
      // CASE: File-to-File (NameLen + Filename + Data)
      const metadataEnd = 1 + nameLen;
      const parsedName = new TextDecoder().decode(peekBuf.subarray(1, metadataEnd));
      const payloadBlob = decryptedBlob.slice(metadataEnd);

      triggerDownload(payloadBlob, parsedName);
      showStatusMsg(`File decrypted: ${parsedName}`, "good");

      if (document.getElementById('mainBox')) {
        document.getElementById('mainBox').innerHTML = `<div>Verified Decrypted File: ${parsedName}</div>`;
      }
    }

    return true;
  } catch (err) {
    console.error("File Decryption Error:", err);
    showStatusMsg("File decryption failed: " + err.message, "bad");
    return false;
  }
}

async function startVerification() {
  const mainBox = document.getElementById('mainBox');
  const rawText = mainBox.innerText.trim();
  if (!rawText) {
    showStatusMsg("Nothing to verify.", "special");
    return;
  }

  // Strip armor and get Base64
  const clean = rawText.replace(/<\/?pre[^>]*>/gi, '').replace(/[\s\r\n]/g, '');
  const blobMatch = clean.match(/[A-Za-z0-9+/]{100,}/);

  if (!blobMatch) {
    showStatusMsg("No certified message found.", "bad");
    return;
  }

  const certifiedArray = decodeBase64(blobMatch[0]);
  return await processVerification(certifiedArray, false);
}

/**
 * Core logic for verifying a certified message.
 * Handles three cases: UI-to-UI (Naked LZ), UI-to-File (Header 0), and File-to-File (Header Len).
 * @param {Uint8Array} certifiedArray - The raw binary starting with marker 150.
 * @param {boolean} isFromFile - Set to true if source is a .pbx file, false if from Base64 text.
 */
async function processVerification(certifiedArray, isFromFile = false) {
  const mainBox = document.getElementById('mainBox');

  if (!certifiedArray || certifiedArray[0] !== 150) {
    showStatusMsg("Not a valid certified message.", "bad");
    return false;
  }

  window.lastDecryptedPadding = certifiedArray.slice(1, 101);
  const signature = certifiedArray.slice(101, 165);
  const payloadData = certifiedArray.slice(165);

  let verificationData;
  if (isFromFile) {
    let runningHash = new Uint8Array(64).fill(0);
    const CHUNK = 64 * 1024;
    let vPos = 0;
    while (vPos < payloadData.length) {
      const chunk = payloadData.slice(vPos, vPos + CHUNK);
      if (chunk.length === 0) break;
      runningHash = await sha512Uint8(concatUi8([runningHash, chunk]));
      vPos += CHUNK;
    }
    verificationData = runningHash;
  } else {
    verificationData = payloadData;
  }

  const hostData = await chrome.storage.sync.get([currentHost, 'locDir']);
  const myLock = hostData[currentHost]?.crypt?.lock;
  const locDir = hostData.locDir || {};

  // (Standard lock resolution logic remains the same...)
  const finalLocks = new Set();
  const priorityLocks = new Set();
  const lockList = document.getElementById('lockList');
  const selectedValues = Array.from(lockList.selectedOptions).map(o => o.value.trim()).filter(s => s);
  if (selectedValues.length > 0) selectedValues.forEach(l => resolveToLocks(l, priorityLocks, locDir, myLock));
  if (myLock) finalLocks.add(myLock);
  Object.values(locDir).forEach(e => { if (e?.lock) resolveToLocks(e.lock, finalLocks, locDir, myLock); });

  const locksToTry = [
    ...Array.from(priorityLocks).map(l => ({ name: (Object.entries(locDir).find(([, v]) => v.lock === l)?.[0] || (l === myLock ? "Me" : l)), lockStr: l })),
    ...Array.from(finalLocks).filter(l => !priorityLocks.has(l)).map(l => ({ name: (Object.entries(locDir).find(([, v]) => v.lock === l)?.[0] || (l === myLock ? "Me" : l)), lockStr: l }))
  ];

  for (const entry of locksToTry) {
    try {
      const lockBin = decodeBase36ToUint8(entry.lockStr);
      if (!lockBin) continue;

      if (nacl.sign.detached.verify(verificationData, signature, lockBin)) {
        // --- PRIORITY: FOLDER KEY CHECK ---
        // If payload is 32 bytes and lacks text structure, activate as key
        if (payloadData.length === 32 && isLikelyFolderKey(payloadData)) {
          window.activeFolderKey = payloadData;
          if (mainBox) mainBox.innerHTML = "Folder Key activated";
          const indicator = document.getElementById('folder-active-indicator');
          if (indicator) indicator.style.display = 'block';
          if (typeof updateFolderKeyUI === 'function') updateFolderKeyUI();
          showStatusMsg(`Verified & Activated Folder Key from: ${entry.name}`, "good");
          return true;
        }

        // --- FALLBACK: STANDARD PAYLOAD HANDLING ---
        if (!isFromFile) {
          const plainText = LZString.decompressFromUint8Array(payloadData);
          mainBox.innerHTML = DOMPurify.sanitize(plainText || new TextDecoder().decode(payloadData));
        } else {
          const typeByte = payloadData[0];
          if (typeByte === 0) {
            const html = LZString.decompressFromUint8Array(payloadData.slice(1));
            mainBox.innerHTML = DOMPurify.sanitize(html || "File Verified");
          } else {
            const nameLen = typeByte;
            const name = new TextDecoder().decode(payloadData.slice(1, 1 + nameLen));
            triggerDownload(new Blob([payloadData.slice(1 + nameLen)]), name);
            mainBox.innerHTML = `<div>Verified Certified File: ${name}</div>`;
          }
        }
        showStatusMsg(`Verified Certificate for: ${entry.name}`, "good");
        return true;
      }
    } catch (e) { continue; }
  }
  showStatusMsg("Certificate could not be verified.", "bad");
  return false;
}

//for the chat feature

function renderChatInviteCard(jsonStr) {
  try {
    const invite = JSON.parse(jsonStr);
    const mainBox = document.getElementById('mainBox');

    // Dynamic host with public fallback
    const targetHost = invite.h || "meet.jit.si";

    mainBox.innerHTML = `
            <div style="padding: 1rem; border: 2px solid #0284c7; border-radius: 0.67rem; background: #f0f9ff; text-align: center; font-family: sans-serif;">
                <h3 style="margin-top: 0; color: #0284c7; font-size: 1.2rem;">Secure P2P Invitation</h3>
                <p style="font-size: 0.93rem; color: #333; margin-bottom: 0.8rem; white-space: pre-wrap; text-align: left;">"${DOMPurify.sanitize(invite.m)}"</p>
                
                <p style="font-size: 0.8rem; color: #0369a1; font-weight: bold; margin-bottom: 0.33rem;">
                    The session Password has been copied to your clipboard.
                </p>
                <p style="font-size: 0.67rem; color: #666; margin-bottom: 0.67rem;">
                    Server: ${targetHost}
                </p>

                <button id="p2p-join-btn" style="width: 100%; padding: 0.8rem; background: #0284c7; color: white; border: none; border-radius: 0.4rem; font-weight: bold; cursor: pointer; margin-bottom: 1rem; font-size: 1rem;">
                    JOIN SECURE ROOM
                </button>

                <div style="text-align: left; background: white; padding: 0.67rem; border-radius: 0.4rem; border: 1px solid #cceeff; font-size: 0.73rem; color: #444; line-height: 1.4;">
                    <div style="margin-bottom: 0.53rem;">
                        <strong>If you are the first to join:</strong>
                        <div style="padding-left: 0.33rem;">
                        - Open 'Security Options' (shield icon).<br>
                        - Enable 'End-to-End Encryption'.<br>
                        - Add a Password and paste from clipboard.
                        </div>
                    </div>
                    <div>
                        <strong>Everyone joining later:</strong>
                        <div style="padding-left: 0.33rem;">
                        - Paste the password from your clipboard when prompted.
                        </div>
                    </div>
                </div>
            </div>
        `;

    document.getElementById('p2p-join-btn').onclick = () => {
      //      navigator.clipboard.writeText(invite.p).then(() => {
      copyAndScheduleClear(invite.p).then(() => {
        showStatusMsg("Room password copied", "good");

        // Hardened Toolbar Whitelist
        const safeButtons = [
          'microphone',
          'camera',
          'desktop',
          'fullscreen',
          'fodeviceselection',
          'hangup',
          'chat',
          'settings',
          'videoquality',
          'tileview',
          'security', // Enables Shield for E2EE/Password
          'e2ee'
        ];

        // Hardened Config String
        const config = `#config.prejoinPageEnabled=false` +
          `&config.e2ee.enabled=true` +
          `&config.disableDeepLinking=true` +
          `&config.doNotStoreRoom=true` +
          `&config.startWithAudioMuted=true` +
          `&config.startWithVideoMuted=true` +
          `&config.p2p.enabled=true` +
          `&config.disableRemoteMute=true` +
          `&config.toolbarButtons=${JSON.stringify(safeButtons)}`;

        // Use the host provided in the decrypted payload
        const jitsiUrl = `https://${targetHost}/${invite.r}${config}`;

        window.open(jitsiUrl, '_blank');

        // Cleanup sensitive data from UI
        setTimeout(() => {
          if (mainBox) mainBox.innerHTML = "";
          showStatusMsg("Session data cleared", "good");
        }, 100);
      });
    };

    showStatusMsg("Chat Invitation Decrypted. Follow the Instructions", "good")
  } catch (e) {
    showStatusMsg("Chat Invite Error: Payload corrupted", "bad");
  }
}

//for PQ modes:

/**
 * Handles Marker 1 (PQ Anonymous) and Marker 73 (PQ Signed) Logic
 */
async function handlePQAnonymousMode(bin, commonData) {
  return handlePQCore(bin, commonData, false);
}

async function handlePQSignedMode(bin, parsed, commonData) {
  const head = (bin instanceof Blob) ? new Uint8Array(await bin.slice(0, 117).arrayBuffer()) : bin.slice(0, 117);
  const recipCount = head[1];
  const SLOT_SIZE = 1160;
  const headerOffset = 117;
  const sigStart = headerOffset + (recipCount * SLOT_SIZE);

  const signature = (bin instanceof Blob)
    ? new Uint8Array(await bin.slice(sigStart, sigStart + 64).arrayBuffer())
    : bin.slice(sigStart, sigStart + 64);

  // RECONSTRUCT CHAINED HASH FROM CHUNKS
  let runningHash = new Uint8Array(64).fill(0);
  const CT_CHUNK_SIZE = (64 * 1024) + 16;
  const totalSize = (bin instanceof Blob) ? bin.size : bin.length;
  let currentPos = sigStart + 64;

  while (currentPos < totalSize) {
    const chunk = (bin instanceof Blob)
      ? new Uint8Array(await bin.slice(currentPos, currentPos + CT_CHUNK_SIZE).arrayBuffer())
      : bin.slice(currentPos, Math.min(currentPos + CT_CHUNK_SIZE, totalSize));

    if (chunk.length === 0) break;
    runningHash = await sha512Uint8(concatUi8([runningHash, chunk]));
    currentPos += CT_CHUNK_SIZE;
  }

  const storage = await chrome.storage.sync.get(['locDir']);
  const locDir = storage.locDir || {};
  let senderName = "Unknown PQ Sender";
  let verifiedSenderKey = null;
  let verified = false;

  const myPub = decodeBase36ToUint8(commonData.base36Lock);
  if (nacl.sign.detached.verify(runningHash, signature, myPub)) {
    verified = true;
    senderName = "Me";
    verifiedSenderKey = myPub;
  }

  if (!verified) {
    const lockList = document.getElementById('lockList');
    const selectedLockStr = lockList?.selectedOptions[0]?.value;
    let locksToTry = [];
    if (selectedLockStr) locksToTry.push({ name: selectedLockStr, lockStr: selectedLockStr });
    Object.entries(locDir).forEach(([name, entry]) => {
      if (entry.lock && entry.lock !== selectedLockStr) locksToTry.push({ name: name, lockStr: entry.lock });
    });

    for (const entry of locksToTry) {
      const pubKey = decodeBase36ToUint8(entry.lockStr);
      if (pubKey && nacl.sign.detached.verify(runningHash, signature, pubKey)) {
        senderName = entry.name;
        verifiedSenderKey = pubKey;
        verified = true;
        break;
      }
    }
  }

  if (!verified) throw new Error("PQ Signature verification failed (Chained Hash mismatch).");

  const result = await handlePQCore(bin, commonData, verifiedSenderKey);
  result.senderName = senderName;
  return result;
}

/**
 * Core decapsulation logic shared by both PQ modes.
 * @param {Uint8Array} bin - The full binary blob.
 * @param {boolean} isSigned - True for Marker 73, False for Marker 1 (Anon).
 */
// --- START OF PQ DECRYPTION ENGINE ---
async function handlePQCore(bin, commonData, senderPubKey = null) {
  try {
    const header = (bin instanceof Blob)
      ? new Uint8Array(await bin.slice(0, 117).arrayBuffer())
      : bin.slice(0, 117);

    const marker = header[0];
    const recipCount = header[1];
    const nonce15 = header.slice(2, 17);
    const nonce24 = makeNonce24(nonce15);
    const padding = header.slice(17, 117);

    // Slot Size: 1088 (KEM) + 24 (Nonce2) + 48 (Wrapped Key) = 1160 bytes
    const SLOT_SIZE = 1160;
    const headerOffset = 117;
    let msgKey = null;

    // --- BLIND PROBING ENGINE ---
    for (let i = 0; i < recipCount; i++) {
      const slotStart = headerOffset + (i * SLOT_SIZE);
      const slot = (bin instanceof Blob)
        ? new Uint8Array(await bin.slice(slotStart, slotStart + SLOT_SIZE).arrayBuffer())
        : bin.slice(slotStart, slotStart + SLOT_SIZE);

      const kemCipher = slot.slice(0, 1088);
      const nonce2 = slot.slice(1088, 1112);
      const wrappedKey = slot.slice(1112, 1160);

      try {
        const mlkemSecret = await noblePostQuantum.ml_kem768.decapsulate(kemCipher, commonData.myPQPair.secretKey);
        msgKey = nacl.secretbox.open(wrappedKey, nonce2, mlkemSecret);
        if (msgKey) break;
      } catch (e) { continue; }
    }

    if (!msgKey) throw new Error("Identity Mismatch: No PQ slot matches your keys.");

    // --- PAYLOAD EXTRACTION ---
    const payloadStart = headerOffset + (recipCount * SLOT_SIZE) + ((marker === 73) ? 64 : 0);

    return {
      success: true,
      msgKey: msgKey,
      nonce: nonce24,
      padding: padding,
      payloadOffset: payloadStart,
      modeLabel: (marker === 73) ? "PQ SIGNED" : "PQ ANONYMOUS"
    };

  } catch (err) {
    console.error("PQ Core Error:", err.message);
    return { success: false, error: err.message };
  }
}
// --- END OF PQ DECRYPTION ENGINE ---

/** * Helper to compare Uint8Arrays 
 */
function u8Equals(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function extractEmbeddedLock(text) {
  const gap = "//////";
  const firstIdx = text.indexOf(gap);

  // Failure guard: If no gap, there is no embedded lock
  if (firstIdx === -1) return { ezLock: null, pqlockBase64: null, ciphertext: text, hasLock: false };

  const ezLock = text.substring(0, firstIdx);
  const remainder = text.substring(firstIdx + gap.length);

  // Jump Check: Is there a PQ Lock of exactly 1579 chars followed by another gap?
  const pqLen = 1579;
  if (remainder.substring(pqLen, pqLen + gap.length) === gap) {
    const pqB64 = remainder.substring(0, pqLen);
    const actualCiphertext = remainder.substring(pqLen + gap.length);

    return {
      ezLock,
      pqlockBase64: pqB64,
      ciphertext: actualCiphertext,
      hasLock: true
    };
  }

  // Fallback: Standard invitation/signed message (Legacy logic)
  // FIX: Explicitly set hasLock to true so the extension processes the ezLock
  return {
    ezLock,
    pqlockBase64: null,
    ciphertext: remainder,
    hasLock: true
  };
}