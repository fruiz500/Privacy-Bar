/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

//this is the content script that runs in the context of web pages. It detects password fields, crypto blobs, and large input areas, and communicates with the background script.
if (typeof window.PB_AGENT_LOADED === 'undefined') {
  window.PB_AGENT_LOADED = true;

  console.log("Privacy Bar: Agent-core injected and active.");

  // Listen for the SCAN_FOR_LOGIN message from background.js
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "SCAN_FOR_LOGIN") {
      // Your logic to check for password fields and report back to sidepanel
      const hasLogin = !!document.querySelector('input[type="password"]');
      console.log("Privacy Bar: Login scan complete. Found:", hasLogin);
    }
  });

  // YOUR ENTIRE EXISTING CODE GOES HERE

  // ---- Helper: Get registered domain ----
  function getRegisteredDomain(hostname) {
    const parts = hostname.toLowerCase().split(".");
    if (parts.length <= 2) return hostname;
    const tld = parts[parts.length - 1];
    const exceptions = ["ai", "io", "me", "tv", "cc", "fm", "am"];
    if (tld.length === 2 && !exceptions.includes(tld)) {
      return parts.slice(parts.length - 3).join(".");
    }
    return parts.slice(parts.length - 2).join(".");
  }

  // ---- Main detection function ----
  function scanPage() {
    // 1. Priority: Large Input Detection
    const hasLargeInputField = checkForLargeInputFields();

    // 2. Password Detection
    const passwordFields = document.querySelectorAll("input[type='password']");
    const passwordCount = passwordFields.length;

    // 3. Refined Crypto Detection
    const bodyText = document.body ? document.body.innerText : "";

    // - Identity separator [cite: 2026-03-28]
    const hasIdentity = bodyText.includes("//////");

    // - PassLok Classic pattern [cite: 2026-03-28]
    const hasClassicPattern = /\b[0-9a-km-zL]{50,}\b/.test(bodyText);

    /**
     * - Unbroken Base64 (Padding-Free) [cite: 2026-04-20]
     * We use \b (word boundaries) to ensure we aren't catching partial strings 
     * inside URLs. We increase the threshold to 128 chars to skip most 
     * standard web tokens and CSS fonts.
     */
    const hasUnbrokenBase64 = /\b[A-Za-z0-9+/]{128,}\b/.test(bodyText);

    const hasCrypto = hasIdentity || hasClassicPattern || hasUnbrokenBase64;

    const state = {
      hasLargeInputField,
      hasPasswords: passwordCount > 0,
      passwordCount,
      hasCrypto,
      host: getRegisteredDomain(window.location.hostname),
    };

    try {
      if (chrome.runtime?.id) {
        // Broadcast for live DOM mutations
        chrome.runtime.sendMessage({ type: "STATE_UPDATE", state });
      } else if (observer) {
        observer.disconnect();
      }
    } catch (e) {
      if (observer) observer.disconnect();
    }

    // Return for the sidepanel handshake [cite: 2026-04-20]
    return state;
  }

  // ---- Large Input Detection ----
  let autoTargetInput = null;
  function checkForLargeInputFields() {
    const candidates = document.querySelectorAll('textarea, [contenteditable]');
    for (const el of candidates) {
      if (el.tagName !== 'TEXTAREA' && !el.isContentEditable) continue;
      const style = window.getComputedStyle(el);
      if (style.display === 'none' || style.visibility === 'hidden') continue;
      if (el.offsetWidth > 100 && el.offsetHeight > 50) {
        autoTargetInput = el;
        return true;
      }
    }
    return false;
  }

  // ---- Identity Injection Helpers ----
  function findUserIdField() {
    const selectors = [
      'input[autocomplete="username"]',
      'input[autocomplete="email"]',
      'input[type="email"]',
      'input[name*="user" i]',
      'input[name*="login" i]',
      'input[id*="user" i]',
      'input[id*="login" i]'
    ];

    for (const selector of selectors) {
      const el = document.querySelector(selector);
      if (el && el.offsetParent !== null) return el;
    }

    // Fallback: first visible text input that isn't a search box
    return Array.from(document.querySelectorAll("input[type='text']"))
      .find(el => el.offsetParent !== null && !el.name.match(/search|q/i));
  }

  // ---- Message Listener ----
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (!chrome.runtime?.id) return;

    if (request.type === "GET_CURRENT_STATE") {
      // FIX: Modified to return the state directly to the caller 
      // instead of triggering a separate STATE_UPDATE message.
      const state = scanPage();
      sendResponse(state);
      return false; // No longer async
    }

    if (request.type === "FILL_PASSWORD") {
      const pwd = request.password;
      const fields = document.querySelectorAll('input[type="password"]');
      if (fields.length > 0) {
        fields.forEach(field => {
          field.value = pwd;
          ['input', 'change', 'keydown', 'keyup'].forEach(ev => field.dispatchEvent(new Event(ev, { bubbles: true })));
          setTimeout(() => { field.value = pwd; field.dispatchEvent(new Event('input', { bubbles: true })); }, 200);
        });
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false });
      }
      return true;
    }

    if (request.type === "INSERT_ENCRYPTED_TEXT") {
      const target = autoTargetInput || document.activeElement;
      if (target && (target.tagName === 'TEXTAREA' || target.isContentEditable)) {
        insertTextAtTarget(target, request.text);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false });
      }
      return true;
    }

    if (request.type === "FILL_IDENTITY") {
      const idField = findUserIdField();
      if (idField && request.userID) {
        idField.value = request.userID;
        ['input', 'change', 'blur'].forEach(ev => idField.dispatchEvent(new Event(ev, { bubbles: true })));
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false });
      }
      return true;
    }
  });

  // ---- Text Insertion Helper ----
  function insertTextAtTarget(target, text) {
    target.focus();
    if (target.tagName === 'TEXTAREA') {
      const start = target.selectionStart;
      const end = target.selectionEnd;
      target.value = target.value.substring(0, start) + text + target.value.substring(end);
    } else {
      const selection = window.getSelection();
      const range = (selection.rangeCount && target.contains(selection.anchorNode))
        ? selection.getRangeAt(0)
        : document.createRange();
      if (!selection.rangeCount || !target.contains(selection.anchorNode)) {
        range.selectNodeContents(target);
        range.collapse(false);
      }
      range.deleteContents();
      const tempDiv = document.createElement("div");
      tempDiv.innerHTML = text;
      const fragment = document.createDocumentFragment();
      while (tempDiv.firstChild) fragment.appendChild(tempDiv.firstChild);
      range.insertNode(fragment);
      selection.removeAllRanges();
      selection.addRange(range);
      selection.collapseToEnd();
    }
    target.dispatchEvent(new Event('input', { bubbles: true }));
  }

  // ---- Click-to-Load Logic ----
  document.addEventListener("click", (e) => {
    if (e.target.tagName === "BUTTON" || e.target.tagName === "INPUT") return;

    // Alt+Click an image to load it into the stego preview
    if (e.altKey && e.target.tagName === "IMG") {
      e.preventDefault();
      e.stopPropagation();

      const imgSrc = e.target.src;

      // Use an async IIFE to handle the fetch without blocking the listener
      (async () => {
        try {
          const response = await fetch(imgSrc);
          if (!response.ok) throw new Error("Failed to fetch original image bytes");

          const blob = await response.blob();
          const reader = new FileReader();

          reader.onloadend = () => {
            chrome.runtime.sendMessage({
              type: "LOAD_STEGO_IMAGE",
              dataUrl: reader.result // This maintains the original MIME type (JPG, GIF, etc.)
            });
          };

          reader.onerror = () => { throw new Error("FileReader failed to process blob"); };
          reader.readAsDataURL(blob);

        } catch (err) {
          // Fallback: if fetch fails (CORS), fall back to URL-based approach
          chrome.runtime.sendMessage({
            type: "LOAD_STEGO_IMAGE",
            url: imgSrc
          });
        }
      })();

      return;
    }

    const blob = getSelectedBlob();
    if (blob) chrome.runtime.sendMessage({ type: "BLOB_CLICKED", blob });
  }, true);

  function getSelectedBlob() {
    const sel = window.getSelection();
    let text = sel.toString().trim();

    if (checkForLargeInputFields()) return null;

    // 1. Target-Aware Extraction (Replacing the "Blind" Parent Climb)
    if (!text) {
      if (sel.rangeCount === 0) return null;
      const range = sel.getRangeAt(0);

      // Get the exact element the user clicked/selected
      let el = range.commonAncestorContainer.nodeType === Node.TEXT_NODE
        ? range.commonAncestorContainer.parentElement
        : range.commonAncestorContainer;

      // --- PROXIMITY CHECK ---
      // Instead of climbing 3 levels blindly, we check if the clicked element
      // or its immediate parent contains the Armor Start/End markers.
      const hasMarkers = (e) => e && (e.innerText.includes('----BEGIN') || e.innerText.includes('=='));

      if (!hasMarkers(el) && !hasMarkers(el.parentElement)) {
        // If we didn't click on an armor block, don't go hunting for one.
        return null;
      }

      // Now that we know we are on an armor block, we can safely expand to get the whole thing
      let depth = 0;
      while (el && !el.innerText.includes('----END') && depth < 3) {
        el = el.parentElement;
        depth++;
      }

      text = el?.innerText || el?.textContent || "";
    }

    // 2. THE ARMOR PIERCER (Your existing logic)
    let armorCleaned = text
      .replace(/-+.*?-+/g, "")
      .replace(/==/g, "")
      .replace(/[^\x20-\x7E]/g, "");

    // 3. THE "GATHERER"
    const blobMatch = armorCleaned.match(/[A-Za-z0-9+/ \r\n\t]{40,}/g);
    if (!blobMatch) return null;

    const longestChunk = blobMatch.reduce((a, b) => a.length > b.length ? a : b);
    const pureBase64 = longestChunk.replace(/[\s\r\n]/g, "");

    // 4. THE VALIDATOR
    if (pureBase64.length > 50) {
      // Standard entropy check
      const vowels = (pureBase64.match(/[aeiouAEIOU]/g) || []).length;
      const ratio = vowels / pureBase64.length;

      const classicLockRegex = /[0-9a-km-zL]{50}\/\/\/\/\/\/+/;
      const hasLock = classicLockRegex.test(pureBase64);

      if (hasLock || ratio < 0.25) {
        return {
          type: "MESSAGE",
          raw: pureBase64,
          hasLock: hasLock
        };
      }
    }
    return null;
  }

  //for page source retrieval when user clicks "Load Page" in the sidepanel
  // Side Panel Listener: Download Sanitized Page
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "get_sanitized_source") {
      sendResponse(getFullSanitizedState());
    }
  });

  function getFullSanitizedState() {
    // 1. Capture all <style> tags and the actual CSS text from <link> tags
    let cssBlocks = "";
    for (let sheet of document.styleSheets) {
      try {
        for (let rule of sheet.cssRules) {
          cssBlocks += rule.cssText + "\n";
        }
      } catch (e) {
        // Some sheets are cross-origin and blocked from reading. Silenced
        //      console.warn("Could not read stylesheet:", sheet.href);
      }
    }

    const bodyClone = document.body.cloneNode(true);
    const baseUrl = window.location.origin + window.location.pathname;

    // Fix paths for any images that DO manage to slip through
    bodyClone.querySelectorAll('[src]').forEach(el => {
      el.setAttribute('src', new URL(el.getAttribute('src'), baseUrl).href);
    });

    return {
      css: cssBlocks, // Send the actual CSS rules as a giant string
      body: bodyClone.innerHTML,
      title: document.title,
      url: window.location.href
    };
  }

  // ---- Observers and Initialization ----
  let scanTimeout = null;
  let observer = new MutationObserver(() => {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(scanPage, 150);
  });
  observer.observe(document.body, { childList: true, subtree: true });

  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") scanPage(); });
  scanPage();

  console.log("Privacy Bar: Agent-core initialized.");

} else {
  console.log("Privacy Bar: Agent already present, skipping re-declaration.");
}