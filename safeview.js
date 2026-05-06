/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url');
const shouldSanitize = urlParams.get('sanitize') === '1'; // Detected from context menu

const frame = document.getElementById('site-frame');
const display = document.getElementById('target-display');
const sanitizedDiv = document.getElementById('sanitized-container');

if (targetUrl) {
  try {
    const url = new URL(targetUrl);
    display.textContent = (shouldSanitize ? "SANITIZED: " : "") + url.hostname;
  } catch(e) {
    display.textContent = targetUrl;
  }

  if (shouldSanitize) {
    // Mode 1: Sanitized Static View
    frame.style.display = 'none';
    sanitizedDiv.style.display = 'block';
    renderSanitizedView(targetUrl);
  } else {
    // Mode 2: Standard Safe View (Live Iframe)
    frame.style.display = 'block';
    sanitizedDiv.style.display = 'none';
    frame.src = targetUrl;
  }
} else {
  document.getElementById('security-bar').innerHTML = "<span><strong>Error:</strong> No URL provided for isolation.</span>";
}

/**
 * Fetches remote content and applies the Panopticon Tally logic.
 */
async function renderSanitizedView(url) {
  const container = document.getElementById('sanitized-container');
  container.innerHTML = "<p style='padding:20px; font-family:sans-serif;'>Fetching and reconstructing isolated environment...</p>";

  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error("HTTP " + response.status);
    const html = await response.text();

    let stats = { images: 0, scripts: 0, active: 0 };

    DOMPurify.addHook('beforeSanitizeElements', (node) => {
      if (node.tagName === 'IMG') {
        stats.images++;
        const altText = node.getAttribute('alt') || 'Image';
        const placeholder = document.createElement('span');
        placeholder.innerText = "[" + altText + "]";
        placeholder.style.cssText = "display:inline-block; font-size:11px; color:#ff5722; border:1px dashed #ff5722; padding:2px 6px; border-radius:3px; cursor:pointer; margin:0 2px; background:#fff5f2; font-family:sans-serif;";
        node.parentNode.insertBefore(placeholder, node);
      }
      if (['SCRIPT', 'NOSCRIPT'].includes(node.tagName)) stats.scripts++;
      if (['IFRAME', 'FORM', 'OBJECT', 'INPUT', 'BUTTON'].includes(node.tagName)) stats.active++;
    });

    const cleanBody = DOMPurify.sanitize(html, {
      FORBID_TAGS: ['script', 'iframe', 'form', 'object', 'embed', 'input', 'button', 'img', 'style', 'link'],
      FORBID_ATTR: ['on*'],
      ADD_ATTR: ['class', 'style', 'href'],
      KEEP_CONTENT: true
    });

    const tallyMsg = "Blocked: " + stats.images + " images, " + stats.scripts + " scripts, and " + stats.active + " active elements.";

    container.innerHTML = `
      <style>
        #sanitized-container { background: #fdfdfd; color: #333; font-family: 'Georgia', serif; line-height: 1.6; padding: 0 0 40px 0; }
        .reader-content { max-width: 800px; margin: 0 auto; padding: 20px; }
        .pb-banner { background: #ff5722; color: white; padding: 12px; text-align: center; font-family: sans-serif; position: sticky; top: 0; z-index: 1000; border-bottom: 2px solid #e64a19; }
        h1, h2, h3 { font-family: sans-serif; color: #111; margin-top: 1.5em; }
        p { margin-bottom: 1.2em; }
        a { color: #0066cc; text-decoration: none; border-bottom: 1px solid #ccc; }
        .reader-content * { max-width: 100%; box-sizing: border-box; }
      </style>
      <div class="pb-banner">
        <strong>Privacy Bar: Sanitized View</strong><br>
        <small>${tallyMsg}</small>
      </div>
      <div class="reader-content">
        ${cleanBody}
      </div>
    `;

    DOMPurify.removeHook('beforeSanitizeElements');
  } catch (err) {
    container.innerHTML = "<p style='color:red; padding:20px; font-family:sans-serif;'><b>Sanitization Failed:</b> " + err.message + "</p>";
  }
}