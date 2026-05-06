/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

/**
 * Privacy Bar Split/Join Logic (HTML Aware)
 * Using mainBox.innerHTML and showStatusMsg(msg, tone)
 */
function splitJoin() {
    //pro feature
    if (!window.checkProGate()) return;

    const mainBox = document.getElementById('mainBox');

    // Get content as HTML to preserve links/formatting
    let content = mainBox.innerHTML.trim();

    // Detection: Look for the PB or legacy tags within the HTML string
    const pbTagRegex = /\[PB-PART-Q(\d{3})\]/;
    const legacyTagRegex = /PL\d{2}p\d{3}/;

    if (pbTagRegex.test(content) || legacyTagRegex.test(content)) {
        // --- JOIN MODE ---
        // Convert HTML line breaks to standard newlines for easier splitting
        let cleanText = content.replace(/<br\s*\/?>/gi, '\n').replace(/<\/div><div>/gi, '\n\n');
        // Strip remaining HTML tags to get just the Base64 data
        let tempDiv = document.createElement('div');
        tempDiv.innerHTML = cleanText;
        let textOnly = tempDiv.innerText;

        const blocks = textOnly.split(/\n\n+/).filter(b => b.trim().length > 0);

        const pbMatch = textOnly.match(pbTagRegex);
        const legacyMatch = textOnly.match(/p(\d{3})/);
        const quorum = pbMatch ? parseInt(pbMatch[1]) : (legacyMatch ? parseInt(legacyMatch[1]) : blocks.length);

        if (blocks.length < quorum) {
            showStatusMsg(`Need ${quorum} parts to join (have ${blocks.length}).`, 'bad');
            return;
        }

        try {
            const processedShares = blocks.map(block => {
                const cleanB64 = block
                    .replace(/\[PB-PART-Q\d{3}\]/g, '')
                    .replace(/PL\d{2}p\d{3}/g, '')
                    .replace(/[\s=\[\]]/g, '');

                const binString = atob(cleanB64);
                const bin = new Uint8Array(binString.length);
                for (let i = 0; i < binString.length; i++) {
                    bin[i] = binString.charCodeAt(i);
                }
                return "8" + Array.from(bin).map(b => b.toString(16).padStart(2, '0')).join('');
            });

            const secretHex = secrets.combine(processedShares);
            const secBin = new Uint8Array(secretHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

            // Decompress back to the original HTML string
            const decryptedHTML = LZString.decompressFromUint8Array(secBin);

            if (!decryptedHTML) throw new Error("Decompression failed");

            // Restore the original HTML content
            mainBox.innerHTML = decryptedHTML;
            showStatusMsg("Parts joined successfully.", 'good');
        } catch (err) {
            showStatusMsg("Error: Could not reconstruct the secret.", 'bad');
            console.error("Join Error:", err);
        }
    } else {
        // --- SPLIT MODE ---
        if (!content || content === "<​br>") {
            showStatusMsg("Nothing to split.", 'bad');
            return;
        }

        const input = prompt("Enter 'Total Parts, Quorum' (e.g., 5,3):", "3,2");
        if (!input) return;

        const parts = input.split(',').map(n => parseInt(n.trim()));
        const n = parts[0];
        const q = parts[1] || n;

        if (isNaN(n) || isNaN(q) || n < 2 || q < 2 || q > n) {
            showStatusMsg("Invalid input. Use 'Total, Quorum'.", 'bad');
            return;
        }

        // Compress the full HTML content
        const compressedBin = LZString.compressToUint8Array(content);
        const hexSecret = Array.from(compressedBin).map(b => b.toString(16).padStart(2, '0')).join('');
        const shares = secrets.share(hexSecret, n, q);

        const qTag = q.toString().padStart(3, '0');

        // Format as plain text blocks separated by double <br> for the UI
        const formattedShares = shares.map(share => {
            const rawHex = share.slice(1);
            const bin = new Uint8Array(rawHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

            let binaryString = '';
            for (let i = 0; i < bin.length; i++) {
                binaryString += String.fromCharCode(bin[i]);
            }
            const b64 = btoa(binaryString).replace(/=/g, '');

            return `[PB-PART-Q${qTag}]<br>${b64}<br>[PB-PART-Q${qTag}]`;
        });

        mainBox.innerHTML = formattedShares.join('<br><br>');
        showStatusMsg(`Split into ${n} parts. Quorum: ${q}.`, 'good');
    }
}