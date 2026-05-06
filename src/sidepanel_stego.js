/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

// Steganography Side Panel Logic
let stegoContainer, stegoPreview, stegoPlaceholder, stegoCapacity, stegoCapacityValue; //stegoActions;

document.addEventListener('DOMContentLoaded', () => {
    const stegoContainer = document.getElementById('stego-image-container');
    const stegoPreview = document.getElementById('stego-image-preview');
    const stegoPlaceholder = document.getElementById('stego-placeholder');
    const stegoCapacity = document.getElementById('stego-capacity-display');
    const stegoCapacityValue = document.getElementById('stego-capacity-value');
    const encryptToImageBtn = document.getElementById('encryptToImageBtn');
    if (encryptToImageBtn) {
        encryptToImageBtn.addEventListener('click', () => {
            // Direct jump to stego encoding, bypassing coreEncrypt
            handleStegoEncode(document.getElementById('stego-format-png').checked);
        });
    }

    const stegoCapacityDisplay = document.getElementById('stego-capacity-display');
    if (stegoCapacityDisplay) {
        stegoCapacityDisplay.addEventListener('click', e => {
            e.stopPropagation();
        });
    }

    // 2. Image Loading Logic
    stegoContainer.addEventListener('click', () => {
        // Unhide compose box and toolbar on click
        const mainBox = document.getElementById('mainBox');
        const toolBar = document.getElementById('toolBar');
        if (mainBox) mainBox.classList.remove('hidden');
        if (toolBar) toolBar.classList.remove('hidden');
        if (mainBox) mainBox.focus();

        //image input logic
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'image/png, image/jpeg';
        input.onchange = (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = (event) => {
                const dataUrl = event.target.result;
                stegoPreview.src = dataUrl;

                // Convert DataURL to Uint8Array immediately and store globally
                // We use a simple fetch here once at load time to handle the Base64 conversion
                fetch(dataUrl).then(res => res.arrayBuffer()).then(buf => {
                    window.currentCoverBytes = new Uint8Array(buf);
                    console.log("Cover bytes stored. Ready for stowaway.");
                });

                stegoPreview.style.display = 'block';
                stegoPlaceholder.style.display = 'none';

                stegoPreview.onload = () => {
                    const isPng = dataUrl.startsWith('data:image/png');
                    updateStegoCapacity(stegoPreview, isPng);
                    const pngRadio = document.getElementById('stego-format-png');
                    const jpgRadio = document.getElementById('stego-format-jpg');
                    if (pngRadio && jpgRadio) {
                        pngRadio.checked = isPng;
                        jpgRadio.checked = !isPng;
                    }
                };
            };
            reader.readAsDataURL(file);
        };
        input.click();
    });

    // 3. Capacity Estimation
    window.updateStegoCapacity = function (img, isPng) {
        const stegoCapacity = document.getElementById('stego-capacity-display');
        const stegoCapacityValue = document.getElementById('stego-capacity-value');
        const stegoActions = document.getElementById('stego-actions');
        const totalPixels = img.naturalWidth * img.naturalHeight;
        let bytes;

        if (isPng) {
            // PNG: 3 bits per pixel (LSB in R, G, B)
            bytes = Math.floor((totalPixels * 3) / 8);
        } else {
            // JPEG: Highly variable, but 10% of pixels is a safe "improved F5" estimate
            bytes = Math.floor(totalPixels * 0.1);
        }

        // Subtract overhead for EOF marker (48 bits = 6 bytes)
        bytes = Math.max(0, bytes - 6);

        stegoCapacityValue.textContent = bytes.toLocaleString();
        stegoCapacity.classList.remove('hidden');

        if (stegoActions) {
            stegoActions.classList.remove('hidden');
            stegoActions.style.display = 'flex'; // Ensure it uses the flex layout
        }
    }
});

// --- Button Listeners ---

/**
 * Handles steganographic encryption for a given format (PNG/JPG).
 * @param {string} format - 'PNG' or 'JPG'
 */
async function handleStegoEncode(isPng, directPayload = null) {
    const imgPreview = document.getElementById('stego-image-preview');
    if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
        showStatusMsg("Please load a cover image first.", "special");
        return;
    }

    // 1. Get the payload: Use the dropped file OR scrape the mainBox
    const payload = directPayload || await getLSBPayload();

    if (!payload || payload.length === 0) {
        showStatusMsg("Nothing to embed.", "special");
        return;
    }

    // 2. Capacity Guard (using the helper we built in Step 3)
    if (isLSBPayloadTooLarge(payload)) return;

    const stegoKey = await getStegoPassword("stego encode");
    if (!stegoKey || stegoKey.trim().length === 0) return;

    try {
        const encodeFunction = isPng ? encodePNG : encodeJPG;
        const resultURI = await encodeFunction({
            image: imgPreview,
            data: payload,
            password: stegoKey,
            skipEncrypt: false,
            iterations: 1
        });

        imgPreview.src = resultURI;

        // --- CLEANUP AFTER SUCCESS ---
        if (!directPayload) {
            mainBox.innerHTML = "";
        }

        showStatusMsg(`File hidden in ${isPng ? 'PNG' : 'JPG'}. Right-click to Save.`, "good");
    } catch (error) {
        console.error("Stego Encoding Error:", error);
        showStatusMsg("Stego error: " + error.message, "bad");
    }
}

/**
 * Gathers the Key and derives the final stretched stego key.
 * Automates via Folder Key if active, otherwise prompts the user.
 */
async function getStegoPassword(label) {
    // 1. Priority: Active Pad File (Highest Entropy)
    if (window.activePadBin) {
        console.log(`Stego: Using SHA-256 hash of active Pad Key for ${label}`);
        
        // Compute SHA-256 of the pad to get a fixed 32-byte key
        const hashBuffer = await crypto.subtle.digest('SHA-256', window.activePadBin);
        return encodeBase64(new Uint8Array(hashBuffer));
    }

    // 2. Priority: Active Folder Key (Raw 32-byte use)
    if (window.activeFolderKey) {
        console.log(`Stego: Using raw Folder Key for ${label}`);
        return encodeBase64(window.activeFolderKey);
    }

    // 3. Automated DH (Direct use of Shared Secret)
    const lockList = document.getElementById('lockList');
    const selected = lockList ? Array.from(lockList.selectedOptions) : [];
    const masterPwd = document.getElementById('m-pass')?.value.trim();
    const myEmail = document.getElementById('user-email')?.value.trim() || "";

    if (selected.length === 1 && masterPwd && myEmail) {
        try {
            const targetLockName = selected[0].value.trim();

            // Derive your identity from DOM credentials
            const common = await prepareCommonData(masterPwd, myEmail);

            const targetLock = targetLockName === 'me' ? common.base36Lock : targetLockName;

            // Convert target's Base36 Lock to Curve25519 Public Key
            const targetPub = ed2curve.convertPublicKey(decodeBase36ToUint8(targetLock));

            // Generate the shared secret (Uint8Array)
            const sharedSecret = makeShared(targetPub, common.myKey);

            console.log(`Stego: Automated DH secret for ${label}`);
            return encodeBase64(sharedSecret);
        } catch (e) {
            // If Master Key check fails or DH error occurs
            console.error("Stego DH failed:", e.message);
        }
    }

    // 4. Fallback: Manual Prompt (Requires Stretching)
    const rawInput = prompt(`Enter stego Key for ${label}:`);
    if (!rawInput) return null;

    const stretched = wiseHash(rawInput, ''); // Only stretch human input
    console.log(`Stego: Using stretched Key for ${label}`);

    return encodeBase64(stretched);
}



document.addEventListener('DOMContentLoaded', () => {
    const imgPreview = document.getElementById('stego-image-preview');

    // Extract and Decrypt Button
    document.getElementById('stego-decrypt-btn').addEventListener('click', async () => {
        const imgPreview = document.getElementById('stego-image-preview');
        if (!imgPreview || !imgPreview.src || imgPreview.style.display === 'none') {
            showStatusMsg("Please load a stego image first.", "special");
            return;
        }

        // 1. Get the key (Using the same static salt used in encryption)
        const stegoKey = await getStegoPassword("stego extract");
        if (!stegoKey) return;

        try {
            const result = await decodeImage({
                image: imgPreview,
                password: stegoKey,
                skipEncrypt: false,
                iterations: 1
            });

            if (result && result.primary && result.primary.length > 0) {
                const data = result.primary;
                const typeByte = data[0];
                const payload = data.subarray(1);
                const mainBox = document.getElementById('mainBox');

                if (typeByte === 0) {
                    // 0x00: LZ-Compressed HTML
                    const decompressed = LZString.decompressFromUint8Array(payload);
                    mainBox.innerHTML = DOMPurify.sanitize(decompressed || new TextDecoder().decode(payload));
                    showStatusMsg("Text extracted.", "good");
                }
                else if (typeByte === 1) {
                    // 0x01: Encrypted Base64 Blob
                    const b64 = encodeBase64(payload);
                    const wrapped = b64.match(/.{1,80}/g).join("\n");
                    mainBox.innerHTML = `<pre>----BEGIN PRIVACY BAR MESSAGE----==\n${wrapped}\n==----END PRIVACY BAR MESSAGE----</pre>`;
                    showStatusMsg("Extraction successful. Use 'Decrypt' to read.", "good");
                }
                else if (typeByte > 1 && typeByte <= 255) {
                    // CASE (A): File with Filename [Len][Name][Data]
                    // Note: 'data' is the full Uint8Array, 'typeByte' is the first byte (Length)
                    try {
                        const nameLen = typeByte;

                        // Extract the filename (starting at index 1, for nameLen bytes)
                        const nameBytes = data.subarray(1, 1 + nameLen);
                        const fileName = new TextDecoder().decode(nameBytes);

                        // The rest is the actual file data
                        const fileBytes = data.subarray(1 + nameLen);

                        if (fileBytes.length === 0) throw new Error("File payload is empty.");

                        // Trigger the download automatically
                        triggerDownload(fileBytes, fileName);

                        showStatusMsg(`Extracted and downloaded: ${fileName}`, "good");
                    } catch (fileErr) {
                        console.error("File extraction failed:", fileErr);
                        showStatusMsg("Extraction error: Could not parse filename.", "bad");
                    }
                }
                else {
                    console.error("Unknown Marker:", typeByte);
                    showStatusMsg("Extraction error: Unknown type byte " + typeByte, "bad");
                }
            } else {
                showStatusMsg("No hidden data found or incorrect Key.", "bad");
            }
        } catch (e) {
            console.error("Stego Decryption Error:", e);
            showStatusMsg("Extraction failed: " + e.message, "bad");
        }
    });
});

function unloadStegoImage() {
    const imgPreview = document.getElementById('stego-image-preview');
    const capacityLabel = document.getElementById('stego-capacity-label');
    const stegoPlaceholder = document.getElementById("stego-placeholder");
    const bottomBar = document.getElementById("stego-capacity-display");

    if (imgPreview) {
        imgPreview.src = "";
        imgPreview.style.display = "none";
        stegoPlaceholder.style.display = "block";
        bottomBar.classList.add('hidden');
    }

    // Reset capacity to 0 since no image is loaded
    if (capacityLabel) {
        capacityLabel.textContent = "0 bytes available";
    }

    //remove data stored for camo
    delete window.currentCoverBytes;

    // Optional: If you have a 'placeholder' text for the drop zone, show it here
    const dropText = document.getElementById('stego-drop-text');
    if (dropText) dropText.style.display = "block";

    showStatusMsg("Image cleared. Drop zone reverted to Pad Key mode.", "good");
}

function cleanBase64(text) {
    // 1. Remove all whitespace, newlines, and carriage returns
    const clean = text.replace(/[\s\r\n]/g, "");

    // Strategy 1: The Lock + ////// + Base64 (Signed/Read-Once)
    const slashMatch = clean.match(/[0-9a-km-zL]{50}\/\/\/\/\/\/[A-Za-z0-9+/]+/);
    if (slashMatch) {
        return slashMatch[0].split("//////")[1];
    }

    // Strategy 2: The Armor Markers == (Anonymous/Signed)
    // We find the first and last occurrence to extract what's inside
    const firstMarkers = clean.indexOf("==");
    const lastMarkers = clean.lastIndexOf("==");

    if (firstMarkers !== -1 && lastMarkers !== -1 && firstMarkers !== lastMarkers) {
        // Extract data between the == pairs
        return clean.substring(firstMarkers + 2, lastMarkers);
    }

    // Strategy 3: Pure "Naked" Base64 
    // If the user pasted just the B64 string without any armor or locks
    const b64Regex = /^[A-Za-z0-9+/]+$/;
    if (clean.length > 64 && b64Regex.test(clean)) {
        return clean;
    }

    return ""; // Not a recognizable binary-in-string format
}

async function getLSBPayload() {
    const mainBox = document.getElementById('mainBox');
    if (!mainBox) return null;

    // --- CASE (A): File Link ---
    const link = mainBox.querySelector('a');
    if (link && (link.href.startsWith('data:') || link.href.startsWith('blob:'))) {
        try {
            const response = await fetch(link.href);
            const fileData = new Uint8Array(await response.arrayBuffer());
            return prepareUnifiedPlaintext(fileData, link.download || "attachment.bin");
        } catch (e) { console.error("Blob fetch failed", e); }
    }

    // --- CASE (B): Encrypted/Certified String ---
    const rawText = mainBox.innerText || mainBox.textContent;
    const cleanedB64 = cleanBase64(rawText);

    if (cleanedB64.length > 32) {
        try {
            const rawBytes = decodeBase64(cleanedB64);
            const payload = new Uint8Array(1 + rawBytes.length);
            payload[0] = 1; // Marker [1] for "Direct B64"
            payload.set(rawBytes, 1);
            return payload;
        } catch (e) { /* Invalid B64, fall through */ }
    }

    // --- CASE (C): Standard Text/HTML ---
    const rawHTML = mainBox.innerHTML.trim();
    const compressed = LZString.compressToUint8Array(rawHTML);
    const payload = new Uint8Array(1 + compressed.length);
    payload[0] = 0; // Marker [0] for "LZ HTML"
    payload.set(compressed, 1);
    return payload;
}

function isLSBPayloadTooLarge(payloadUint8) {
    const capacityValue = document.getElementById('stego-capacity-value');
    if (!capacityValue) return false;

    // Extract the number from your UI (e.g., "1024 bytes available")
    const maxBytes = parseInt(capacityValue.textContent.replace(/\D/g, ''), 10);
    const required = payloadUint8.length;

    if (required > maxBytes) {
        const diff = required - maxBytes;
        showStatusMsg(`Too large! Need ${required} bytes, but image only holds ${maxBytes} (Short by ${diff}).`, "bad");
        return true;
    }

    return false;
}

// Attach the listener
document.getElementById('unload-image-btn').addEventListener('click', unloadStegoImage);

// IMPORTANT: Update your existing image loading logic (where you set imgPreview.src) 
// to include this line so the button appears when an image is loaded:
// document.getElementById('unload-image-btn').style.display = "inline-block";

function prepareStegoPayload() {
    const mainBox = document.getElementById('mainBox');
    const rawContent = mainBox.innerText.trim();

    // 1. Check for Encrypted Binary Data (Base64)
    const lockRegex = /[a-kLm-z0-9]{50}\/\/\/\/\/\//;
    const stripped = rawContent.replace(lockRegex, '').replace(/[\s\r\n]/g, '');
    const b64Matches = stripped.match(/[A-Za-z0-9+/]{50,}/g);

    if (b64Matches) {
        const cleanContent = b64Matches.reduce((a, b) => a.length > b.length ? a : b);
        try {
            const binaryData = decodeBase64(cleanContent);
            const payload = new Uint8Array(binaryData.length + 1);
            payload[0] = 0x01; // Binary/Encrypted Marker
            payload.set(binaryData, 1);
            return payload;
        } catch (e) { /* fall back to text */ }
    }

    // 2. TEXT MODE: Compress innerHTML with LZString
    const richText = mainBox.innerHTML;
    // compressToUint8Array is the gold standard for binary stego
    const compressed = LZString.compressToUint8Array(richText);

    const payload = new Uint8Array(compressed.length + 1);
    payload[0] = 0x00; // Text Marker (Now implicitly compressed)
    payload.set(compressed, 1);

    console.log(`Stego Prep: Compressed ${richText.length} chars to ${compressed.length} bytes.`);
    return payload;
}

//the following is for the high-capacity but not so stealthy "stowaway" stego, which attaches encrypted material to the end of a PNG or JPG image EOF

// PNG EOF: IEND chunk + CRC
const PNG_EOF = new Uint8Array([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
// JPEG EOF: Standard marker
const JPG_EOF = new Uint8Array([0xFF, 0xD9]);

async function attachBlobToImage(encryptedBlob) {
    if (!window.currentCoverBytes) {
        showStatusMsg("No cover image data found.", "bad");
        return;
    }

    // 1. Start with a clean copy of the original cover
    let imageBytes = new Uint8Array(window.currentCoverBytes);

    // 2. Determine format and EOF marker
    let eofIndex = -1;
    let extension = "png"; // Default

    // Check for JPEG Magic Bytes: FF D8
    if (imageBytes[0] === 0xFF && imageBytes[1] === 0xD8) {
        extension = "jpg";
        const idx = findSequence(imageBytes, JPG_EOF);
        if (idx !== -1) eofIndex = idx + JPG_EOF.length;
    } else {
        // Assume PNG (Magic Bytes: 89 50 4E 47)
        extension = "png";
        const idx = findSequence(imageBytes, PNG_EOF);
        if (idx !== -1) eofIndex = idx + PNG_EOF.length;
    }

    // 3. Prune: Remove any existing data after the image EOF
    if (eofIndex !== -1 && eofIndex < imageBytes.length) {
        imageBytes = imageBytes.slice(0, eofIndex);
    }

    // 4. Glue: Append the encrypted payload
    // Create a copy to avoid mutating the original data in the UI
    const obfuscatedBlob = new Uint8Array(encryptedBlob);

    // XOR Byte 0 (Mode) with Byte 2 (Random Noise)
    // Formula: Byte0 = Byte0 ^ Byte2
    if (obfuscatedBlob.length > 1) {
        obfuscatedBlob[0] = obfuscatedBlob[0] ^ obfuscatedBlob[2];
        obfuscatedBlob[1] = obfuscatedBlob[1] ^ obfuscatedBlob[3];
    }

    const resultFile = concatUi8([imageBytes, obfuscatedBlob]);

    // 5. Download: Match the original extension
    triggerDownload(resultFile, `camo_image_${Date.now()}.${extension}`);

    showStatusMsg(`Stowaway attached to ${extension.toUpperCase()}.`, "good");
}

/**
 * Standard Byte Sequence Search
 */
function findSequence(data, seq) {
    for (let i = 0; i < data.length - seq.length; i++) {
        let match = true;
        for (let j = 0; j < seq.length; j++) {
            if (data[i + j] !== seq[j]) { match = false; break; }
        }
        if (match) return i;
    }
    return -1;
}

async function checkImageForStowaway(file, fileName) {
    // 1. Efficiently find the EOF marker in the first 5MB
    const scanLimit = Math.min(file.size, 5 * 1024 * 1024);
    const headBuf = await file.slice(0, scanLimit).arrayBuffer();
    const headBytes = new Uint8Array(headBuf);

    let eofIndex = -1;
    const pngIdx = findSequence(headBytes, PNG_EOF);
    if (pngIdx !== -1) {
        eofIndex = pngIdx + PNG_EOF.length;
    } else {
        const jpgIdx = findSequence(headBytes, JPG_EOF);
        if (jpgIdx !== -1) eofIndex = jpgIdx + JPG_EOF.length;
    }

    // No appended data found (8 bytes is minimum for a PBX header)
    if (eofIndex === -1 || eofIndex >= file.size - 8) return false;

    // 2. Extract and fix the XOR "Taint" on the first 4 bytes
    const stowHeaderBlob = file.slice(eofIndex, eofIndex + 4);
    const stowHeader = new Uint8Array(await stowHeaderBlob.arrayBuffer());

    // Reverse the obfuscation: Byte0 = Byte0 ^ Byte2
    if (stowHeader.length >= 4) {
        stowHeader[0] = stowHeader[0] ^ stowHeader[2];
        stowHeader[1] = stowHeader[1] ^ stowHeader[3];
    }

    // 3. Reconstruct as a Blob to support chunked decryption and metadata peeking
    const stowawayBlob = new Blob([
        stowHeader,
        file.slice(eofIndex + 4)
    ]);

    console.log("Camo/Stowaway detected. Extracted size:", stowawayBlob.size);

    // 4. Hand-off the Blob to the decrypter
    await processFileDecryption(stowawayBlob, fileName + ".dec");
    return true;
}

//for text-based camo of 32-byte items

// --- High-Contrast Jargon Buckets ---
const BUCKETS = [
    ["hello", "dear", "hi", "greetings", "regarding", "attached", "concerning", "updated", "hey", "summary", "details", "information", "status", "re", "note", "message"],
    ["reviewing", "checking", "studying", "tracking", "monitoring", "analyzing", "verifying", "sorting", "auditing", "finalizing", "indexing", "organizing", "mapping", "evaluating", "validating", "updating"],
    ["updated", "strategic", "quarterly", "archived", "external", "internal", "sensitive", "operational", "technical", "detailed", "weekly", "monthly", "primary", "secondary", "global", "local"],
    ["dashboard", "presentation", "overview", "dataset", "projection", "brief", "manifest", "spreadsheet", "log", "folder", "database", "report", "file", "record", "chart", "schema"],
    ["immediately", "totally", "partially", "today", "securely", "eventually", "efficiently", "promptly", "regularly", "carefully", "thoroughly", "strictly", "smoothly", "properly", "quickly", "finally"]
];

function getShuffledSlot(idx, pass) {
    SeededPRNG.seed(pass + idx);

    let arr;
    if (idx === 0) {
        // Slot 0 always uses the Greetings (Bucket 0)
        arr = [...BUCKETS[0]];
    } else {
        // Slots 1-64 rotate through the Data Buckets (Buckets 1-4)
        // We use (idx - 1) % 4 + 1 to ensure we stay within the data bucket range
        const bucketIdx = ((idx - 1) % 4) + 1;
        arr = [...BUCKETS[bucketIdx]];
    }

    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(SeededPRNG.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

function wrapToMessengerHTML(uint8Data, pass, type = "folder") {
    if (uint8Data.length !== 32) return "";

    let d = [];

    // 1. PUSH THE GREETING FIRST (Slot 0)
    const typeNibble = (type === "folder") ? 0 : 1;
    d.push(getShuffledSlot(0, pass)[typeNibble]);

    // 2. PUSH THE DATA (Slots 1 through 64)
    for (let i = 0; i < 32; i++) {
        const byte = uint8Data[i];
        // We now use i*2+1 and i*2+2 to leave slot 0 for the greeting
        d.push(getShuffledSlot(i * 2 + 1, pass)[(byte >> 4) & 0x0F]);
        d.push(getShuffledSlot(i * 2 + 2, pass)[byte & 0x0F]);
    }

    // --- NARRATIVE ASSEMBLY ---
    let s = `${d[0]} Jim,\n\n`; // Uses d[0]

    // Body uses d[1] through d[64]
    s += `I spent some time ${d[1]} the ${d[2]} ${d[3]} which we received ${d[4]}. `;
    s += `It appears that ${d[5]} the ${d[6]} ${d[7]} was done ${d[8]}. `;
    s += `After ${d[9]} the ${d[10]} ${d[11]}, everything was saved ${d[12]}. \n\n`;
    s += `We are currently ${d[13]} the ${d[14]} ${d[15]} to ensure it's handled ${d[16]}. `;
    s += `I've noticed that ${d[17]} the ${d[18]} ${d[19]} helps us to work ${d[20]}. `;
    s += `By ${d[21]} the ${d[22]} ${d[23]}, the team finished ${d[24]}. \n\n`;
    s += `Please consider ${d[25]} the ${d[26]} ${d[27]} as soon as it's ready ${d[28]}. `;
    s += `Our goal of ${d[29]} the ${d[30]} ${d[31]} should be achieved ${d[32]}. `;
    s += `I'll keep ${d[33]} the ${d[34]} ${d[35]} until it's processed ${d[36]}. \n\n`;
    s += `While ${d[37]} the ${d[38]} ${d[39]}, I found that it works ${d[40]}. `;
    s += `Everyone is ${d[41]} the ${d[42]} ${d[43]} and we should have it ${d[44]}. `;
    s += `Once we finish ${d[45]} the ${d[46]} ${d[47]}, please notify me ${d[48]}. \n\n`;
    s += `If you're ${d[49]} the ${d[50]} ${d[51]}, let's finalize it ${d[52]}. `;
    s += `The task of ${d[53]} the ${d[54]} ${d[55]} is moving along ${d[56]}. `;
    s += `By ${d[57]} the ${d[58]} ${d[59]}, we can finish ${d[60]}. `;
    s += `I'm still ${d[61]} the ${d[62]} ${d[63]} so it's ready ${d[64]}.`;

    // --- HIGHLIGHTER FIX ---
    const rawWords = s.split(/(\s+)/);
    let tempWords = s.toLowerCase().replace(/[?.!,:;]/g, " ").split(/\s+/).filter(w => w.length > 0);
    let activeIndices = new Set();
    let tPtr = 0;

    // Loop must run 65 times (0 to 64) to highlight all keywords
    for (let i = 0; i < 65; i++) {
        const shuffled = getShuffledSlot(i, pass);
        while (tPtr < tempWords.length && shuffled.indexOf(tempWords[tPtr]) === -1) tPtr++;
        if (tPtr < tempWords.length) { activeIndices.add(tPtr); tPtr++; }
    }

    let html = "";
    let wordCount = 0;
    rawWords.forEach(w => {
        if (/\s+/.test(w)) { html += w; }
        else {
            if (activeIndices.has(wordCount)) html += `<span style="background-color: #fff3cd;">${w}</span>`;
            else html += w;
            wordCount++;
        }
    });
    return html.replace(/\n/g, '<br>');
}

function isMessengerNarrative(text) {
    if (!text) return false;
    const lowerText = text.toLowerCase();

    // A larger list of words drawn directly from your BUCKETS
    const markers = [
        "reviewing", "financial", "report", "immediately",
        "spreadsheet", "analyzing", "quarterly", "document",
        "promptly", "optimized", "dataset", "operational"
    ];

    // If the pasted text contains at least 3 of these, trigger the prompt
    const score = markers.reduce((acc, word) => acc + (lowerText.includes(word) ? 1 : 0), 0);
    return score >= 3;
}

function handleRecoveredMessengerData(result) {
    if (!result) return;

    const { type, data } = result;

    // Type 0 (from "Hello/Hi" etc.) = Folder Key
    if (type === 0) {
        window.activeFolderKey = data;
        if (typeof updateFolderKeyUI === 'function') updateFolderKeyUI();
        showStatusMsg("Folder Key automatically identified and activated.", "good");
    }
    // Type 1 (from "Dear/Greetings" etc.) = User Lock
    else if (type === 1) {
        const name = prompt("User Lock detected. Enter name for Directory:", "New Contact");
        if (name) {
            const b64 = encodeBase64(data);
            const b36Lock = changeBase(b64, base64, base36, true);
            saveToLocDir(name, b36Lock);
            showStatusMsg(`Saved Lock for '${name}' to Directory.`, "good");
        }
    }
    else {
        // This is why it was silent. It found a nibble like 2, 3, or 15.
        showStatusMsg(`Unrecognized Narrative Type (Nibble: ${type}).`, "bad");
    }
}

// Helper to update the directory storage
function saveToLocDir(name, lockB36) {
    chrome.storage.sync.get(['locDir'], (res) => {
        const dir = res.locDir || {};
        dir[name] = lockB36;
        chrome.storage.sync.set({ locDir: dir }, () => {
            window.locDir = locDir;
            if (window.updateLockList) window.updateLockList();
            showStatusMsg(`Lock saved for ${name}.`, "good");
        });
    });
}

/**
 * RECOVERY ENGINE: Extracts 32 bytes from a Messenger Narrative
 */
function runUnwrapToUint8(text, pass) {
    const words = text.toLowerCase().replace(/[?.!,:;]/g, " ").split(/\s+/).filter(w => w.length > 0);
    let ptr = 0;
    let nibbles = [];

    try {
        // --- PHASE 1: FIND THE GREETING (SLOT 0) ---
        const greetingShuffled = getShuffledSlot(0, pass);
        let typeHeader = -1;

        for (; ptr < words.length; ptr++) {
            const val = greetingShuffled.indexOf(words[ptr]);
            if (val !== -1) {
                typeHeader = val;
                nibbles.push(typeHeader); // Nibble 0 is now Locked
                ptr++;
                break;
            }
        }

        if (typeHeader === -1) throw "Greeting not found";

        // --- PHASE 2: DATA SLOTS (1 through 64) ---
        // CRITICAL: We start i at 1, NOT 0.
        for (let i = 1; i < 65; i++) {
            const shuffled = getShuffledSlot(i, pass);

            let foundDataWord = false;
            while (ptr < words.length) {
                const val = shuffled.indexOf(words[ptr]);
                if (val !== -1) {
                    nibbles.push(val);
                    ptr++; // Move to next word for the next slot
                    foundDataWord = true;
                    break;
                }
                ptr++; // Skip "Jim", "the", "which", etc.
            }

            if (!foundDataWord) throw "Sync lost at slot " + i;
        }

        // --- PHASE 3: PACKING ---
        // (Same as before: nibbles[1] and [2] make Byte 0)
        let uint8Result = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            uint8Result[i] = (nibbles[i * 2 + 1] << 4) | nibbles[i * 2 + 2];
        }
        return { type: typeHeader, data: uint8Result };

    } catch (e) {
        console.error("Messenger Recovery Error:", e);
        return null;
    }
}

/**
 * Processes the raw prompt input. 
 * Returns the original string if empty, or a 32-byte stretched key if not.
 */
function getStretchedSeed(rawPass) {
    if (!rawPass || rawPass === "") return ""; // No penalty for empty Key

    // Use a constant salt so the receiver can replicate the hash
    const salt = "messenger-narrative-salt";
    const stretched = wiseHash(rawPass, salt);

    // Convert the Uint8Array to a string or hex for the SeededPRNG
    return Array.from(stretched).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Processes the unwrapped 65-nibble package.
 * @param {Object} result - The {type, data} object from runUnwrapToUint8
 */
function handleMessengerRecovery(result) {
    if (!result) {
        showStatusMsg("Could not recover data from narrative.", "bad");
        return;
    }

    const { type, data } = result;

    if (type === 0) {
        // Type 0: Folder Key (Used for encrypting files/notes)
        window.activeFolderKey = data;

        // Refresh your UI elements that show the active key
        if (typeof updateFolderKeyUI === "function") updateFolderKeyUI();

        showStatusMsg("Folder Key automatically identified and loaded.", "good");

    } else if (type === 1) {
        // Type 1: User Lock (A Public Key for the Directory)
        const name = prompt("User Lock detected in narrative. Save to Directory as:", "New Contact");

        if (name) {
            // Convert the 32-byte Uint8Array back to your Base36 format for storage
            const b64 = encodeBase64(data);
            const b36Lock = changeBase(b64, base64, base36, true);

            // Assuming your save function exists
            saveToLocDir(name, b36Lock);
            showStatusMsg(`Saved Lock for '${name}' to Directory.`, "good");
        }
    } else {
        showStatusMsg("Unknown data type detected in narrative.", "bad");
    }
}