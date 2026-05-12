/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch((error) => console.error(error));

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

chrome.runtime.onInstalled.addListener(() => {
  console.log("Privacy Bar Installed");

  if (chrome.contextMenus) {
    chrome.contextMenus.create({
      id: "openSafeView",
      title: "Open link in Privacy Bar Safe View",
      contexts: ["link"]
    });

    chrome.contextMenus.create({
      id: "openSanitized",
      title: "Open Sanitized Link in Privacy Bar",
      contexts: ["link"]
    });
  }
});

if (chrome.contextMenus) {
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (!info.linkUrl) return;

    const isSanitized = info.menuItemId === "openSanitized";
    const baseUrl = chrome.runtime.getURL("safeview.html");

    // Routing: Both go to safeview.html, but one gets the sanitize flag
    const targetUrl = `${baseUrl}?url=${encodeURIComponent(info.linkUrl)}${isSanitized ? '&sanitize=1' : ''}`;

    chrome.tabs.create({ url: targetUrl });
  });
}

// Rules to strip headers that prevent iframing (X-Frame-Options and CSP)
const SAFE_VIEW_RULES = [
  {
    id: 1,
    priority: 1,
    action: {
      type: "modifyHeaders",
      responseHeaders: [
        { header: "x-frame-options", operation: "remove" },
        { header: "content-security-policy", operation: "remove" },
        { header: "frame-options", operation: "remove" }
      ]
    },
    condition: {
      // Only apply these rules when the initiator is our own extension's Safe View page
      initiatorDomains: [chrome.runtime.id],
      resourceTypes: ["sub_frame"]
    }
  }
];

// 1. Move the rule application into a named function
async function applyProIframeRules() {
  const hasPermission = await chrome.permissions.contains({
    permissions: ['declarativeNetRequest']
  });

  if (hasPermission) {
    // Use updateDynamicRules so the rules persist across browser restarts
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [1],
      addRules: SAFE_VIEW_RULES
    });
    console.log("Privacy Bar: Safe View rules active.");
  }
}

// 2. Listen for the "Pro" permission being added (triggered in license.js)
chrome.permissions.onAdded.addListener((permissions) => {
  if (permissions.permissions.includes('declarativeNetRequest')) {
    applyProIframeRules();
  }
});

// 3. Attempt to apply rules on startup/install (will only succeed for Pro users)
chrome.runtime.onInstalled.addListener(applyProIframeRules);
applyProIframeRules();

//to inject content script
// Track if the side panel is currently "open" in the active window
let isPanelOpen = false;

// 1. Listen for Tab Activation (User clicks a different tab)
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  if (isPanelOpen) {
    injectAgentToTab(activeInfo.tabId);
  }
});

/**
 * RE-INJECTION ON RELOAD: 
 * Watches for navigation/reloads and pushes the agent if the panel is open
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  const { isPanelOpen } = await chrome.storage.session.get("isPanelOpen");

  // 2. SILENT EXIT: Avoid trying to 'help' on restricted pages.
  if (isRestrictedUrl(tab.url)) return;

  if (changeInfo.status === 'complete' && isPanelOpen) {
    chrome.runtime.sendMessage({ action: "RELOAD_SYNC", tabId: tabId });
  }
});

// Consolidate injection logic into one robust helper
async function injectAgentToTab(tabId) {
  try {
    // 1. Blind Injection attempt
    // No URL or permissions check needed; the activeTab gesture handles it
    await chrome.scripting.executeScript({
      target: { tabId: tabId },
      files: ["agent-core.js"]
    });

    // 2. Handshake
    chrome.tabs.sendMessage(tabId, { type: "GET_CURRENT_STATE" });
    return { success: true };

  } catch (err) {
    console.log("Privacy Bar: Injection blocked (likely a restricted page).", err.message);
    return { success: false, error: "INJECTION_FAILED" };
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "PANEL_ACTIVE") {
    if (!request.tabId) {
      sendResponse({ success: false, error: "MISSING_ID" }); // FIX: Respond before exiting
      return false;
    }

    chrome.storage.session.set({ isPanelOpen: true });

    // Use a catch to ensure sendResponse is called on rejection
    injectAgentToTab(request.tabId)
      .then(res => sendResponse(res))
      .catch(err => sendResponse({ success: false, error: err.message }));

    return true;
  }

  if (request.action === "PANEL_CLOSED") {
    chrome.storage.session.set({ isPanelOpen: false });
    // No return true needed here as we aren't responding
  }
});

chrome.action.onClicked.addListener((tab) => {
  const tabId = tab.id;
  const url = tab.url; // Capture the activeTab gift immediately

  // 1. Fire and forget the storage set (don't await it here)
  chrome.storage.session.set({ activeTabUrl: url, activeTabId: tabId });

  // 2. Open the panel IMMEDIATELY to satisfy the 'User Gesture' rule 
  chrome.sidePanel.setOptions({
    tabId,
    path: 'sidepanel.html',
    enabled: true
  }, () => {
    // Calling open inside the callback of a gesture-triggered function 
    // is the most reliable way to avoid the "Uncaught Error"
    chrome.sidePanel.open({ tabId }).catch(err => console.error("Gesture Error:", err));
  });
});

/**
 * THE REAPER: Wipes the Master Key from session storage when the alarm fires.
 * This ensures the session is killed even if the sidepanel is closed.
 */
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "SPAlarm") {
    chrome.storage.session.remove("masterPwd", () => {
      console.log("Privacy Bar: Security Timeout. Master Key wiped from session.");
      // Optional: Notify the sidepanel to refresh the UI if it's open
      chrome.runtime.sendMessage({ action: "SESSION_WIPED" });
    });
  }
});