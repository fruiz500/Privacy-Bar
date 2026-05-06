/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

// PolyCrypt2 Human Crypto Logic

const base26 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/**
 * Parses a human-readable key string into component parts.
 * @param {string} keyStr - The key string in format: k1,k2,k3,k4,k5[,nonce]
 * @returns {Object|null} - Parsed key object or null if invalid.
 */
function parseHumanKey(keyStr) {
    if (!keyStr) return null;
    const parts = keyStr.split(',').map(p => p.trim());
    if (parts.length >= 5) {
        return {
            k1: parts[0], k2: parts[1], k3: parts[2], k4: parts[3], k5: parts[4],
            serp: parseInt(parts[5]) || 2 // Defaults to 2 if missing or NaN
        };
    }
    return null;
}

/**
 * Generates a mixed alphabet for a given key string.
 * @param {string} string - The key string to derive the alphabet from.
 * @returns {string} - The 26-letter mixed alphabet.
 */
function humanMakeAlphabet(string) {
    string = string.toUpperCase().replace(/[^A-Z]/g, '');
    let result = '';
    // NOTE: The standalone uses reversed alpha "ZYX..."
    let alpha = "ZYXWVUTSRQPONMLKJIHGFEDCBA";
    const base26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for (let i = 0; i < string.length; i++) {
        let letter = string.charAt(i);
        if (result.indexOf(letter) === -1) {
            // Letter not picked yet, add it normally
            result += letter;
            alpha = alpha.replace(letter, '');
        } else {
            // Letter was picked, find substitute from alpha
            let index = base26.indexOf(letter);
            let substituted = false;

            // Find first letter in alpha that comes BEFORE the duplicate in base26
            for (let j = 0; j < alpha.length; j++) {
                let alphaChar = alpha.charAt(j);
                if (base26.indexOf(alphaChar) < index) {
                    result += alphaChar;
                    alpha = alpha.slice(0, j) + alpha.slice(j + 1);
                    substituted = true;
                    break;
                }
            }

            // If no earlier letter found, take the first available letter
            if (!substituted && alpha.length > 0) {
                result += alpha.charAt(0);
                alpha = alpha.slice(1);
            }
        }
    }

    // Append any remaining letters from the reversed alpha
    return result + alpha;
}

/**
 * Encrypts or decrypts text using the PolyCrypt2 method.
 * @param {string} text - The plaintext or ciphertext.
 * @param {Object} hKey - The parsed human key object.
 * @param {boolean} isEncrypt - True for encryption, false for decryption.
 * @returns {string} - The resulting ciphertext or plaintext.
 */
function humanEncryptDecrypt(text, hKey, isEncrypt) {
    const base26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const alphabets = [
        humanMakeAlphabet(hKey.k1), // base26B1
        humanMakeAlphabet(hKey.k2), // base26B2
        humanMakeAlphabet(hKey.k3), // base26B3
        humanMakeAlphabet(hKey.k4)  // base26B4
    ];

    const arr = []; // Equivalent to base26BArray1, 2, 3, 4
    const inv = []; // Equivalent to base26Binverse1, 2, 3, 4

    for (let i = 0; i < 4; i++) {
        const mixedAlpha = alphabets[i];
        arr[i] = new Int32Array(26);
        inv[i] = new Int32Array(26);

        for (let j = 0; j < 26; j++) {
            // arr[i][j] = base26.indexOf(mixedAlpha.charAt(j))
            arr[i][j] = base26.indexOf(mixedAlpha[j]);

            // inv[i][j] = mixedAlpha.indexOf(base26.charAt(j))
            inv[i][j] = mixedAlpha.indexOf(base26[j]);
        }
    }

    const key5 = hKey.k5.toUpperCase().replace(/[^A-Z]/g, '');
    const seedLen = key5.length;
    const input = text.toUpperCase().replace(/[^A-Z]/g, '');

    let nonce = '', ciphertext;
    if (isEncrypt) {
        while (nonce.length < seedLen) {
            const byte = new Uint8Array(1);
            crypto.getRandomValues(byte);
            // 26 * 9 = 234. We reject any value >= 234 to eliminate modulo bias.
            if (byte[0] < 234) {
                nonce += base26[byte[0] % 26];
            }
        }
        ciphertext = input;
    } else {
        nonce = input.substring(0, seedLen);
        ciphertext = input.substring(seedLen);
    }

    const nonceIndices = Array.from(nonce).map(c => base26.indexOf(c));
    const key5Indices = Array.from(key5).map(c => base26.indexOf(c));

    // 1. Pre-allocate Keystream (Seed + Ciphertext length)
    const stream = new Int32Array(seedLen + ciphertext.length);

    // 2. Generate Actual Seed
    for (let i = 0; i < seedLen; i++) {
        stream[i] = arr[1][(26 + key5Indices[i] - inv[0][nonceIndices[i]]) % 26];
    }

    // 3. Generate Keystream (Lagged Fibonacci)
    const serp = hKey.serp;
    const globalSign = Math.pow(-1, serp);
    const tapInterval = Math.floor((seedLen - 1) / (serp - 1)) || 1;

    for (let i = 0; i < ciphertext.length; i++) {
        let sign = 1;
        let partSum = 26 * Math.floor(serp / 2) - globalSign * inv[2][stream[i]];
        for (let j = 1; j < serp; j++) {
            partSum += stream[i + j * tapInterval] * globalSign * sign;
            sign = -sign;
        }
        stream[i + seedLen] = arr[3][(partSum + 26) % 26];
    }

    // 4. Final Transformation: Map 0-25 indices to A-Z characters
    let resultChars = new Array(ciphertext.length);
    for (let i = 0; i < ciphertext.length; i++) {
        const charIdx = base26.indexOf(ciphertext[i]);
        const nextK = stream[i + seedLen];
        let finalIdx;

        if (isEncrypt) {
            finalIdx = arr[1][(26 - inv[0][charIdx] + nextK) % 26];
        } else {
            finalIdx = arr[0][(26 - inv[1][charIdx] + nextK) % 26];
        }
        // Look up the actual letter in the base26 constant
        resultChars[i] = base26[finalIdx];
    }

    const finalStr = resultChars.join('');
    return isEncrypt ? (nonce + finalStr) : finalStr;
}

//functions for pad mode. First, helper functions:

async function compressionEntropy(bytes) {
  // Convert Uint8Array to binary string (lossless)
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  
  // Use browser's native Deflate via Blob API (approximation)
  const blob = new Blob([binary], { type: 'application/octet-stream' });
  const reader = new FileReader();
  
  return new Promise((resolve) => {
    reader.onload = () => {
      const compressedSize = reader.result.byteLength;
      const ratio = compressedSize / bytes.length;
      // Normalize to 0-1 scale (higher = more entropy)
      resolve(Math.min(1, ratio * 2)); 
    };
    reader.readAsArrayBuffer(blob);
  });
}

function enhancedShannonEntropy(array, base = 256) {
  const length = array.length;
  const freqArray = new Array(base).fill(0);
  
  // 1. Global Shannon Frequency
  for (let i = 0; i < length; i++) {
    freqArray[array[i]]++;
  }
  
  let shannon = 0;
  for (let i = 0; i < base; i++) {
    if (freqArray[i] > 0) {
      const p = freqArray[i] / length;
      shannon -= p * (Math.log(p) / Math.LN2);
    }
  }
  const normalizedShannon = shannon / 8; // Max entropy for 8-bit is 8

  // 2. Local Variance (Sliding Window)
  const windowSize = Math.min(64, Math.floor(length / 4));
  let sum = 0, sumSquares = 0, count = 0;
  
  for (let i = 0; i <= length - windowSize; i++) {
    let windowSum = 0;
    for (let j = 0; j < windowSize; j++) {
      windowSum += array[i + j];
    }
    const mean = windowSum / windowSize;
    sum += mean;
    sumSquares += mean * mean;
    count++;
  }
  
  const variance = (sumSquares / count) - Math.pow(sum / count, 2);
  const normalizedVariance = Math.min(1, variance / 64); // Heuristic normalization

  // 3. Combined Score (Weighted Average)
  return 0.7 * normalizedShannon + 0.3 * normalizedVariance;
}

async function getChunkEntropy(bytes) {
  const shannonScore = enhancedShannonEntropy(bytes);
  const compressionScore = await compressionEntropy(bytes);
  
  // Weighted average (favor compression for robustness)
  return 0.3 * shannonScore + 0.7 * compressionScore;
}

function calculateOptimalChunkSize(entropyScore) {
  // Map entropy (0.0 to 1.0) to chunk size (e.g., 1KB to 64KB)
  const minSize = 1024;
  const maxSize = 65536;
  return Math.round(minSize + (maxSize - minSize) * entropyScore);
}

async function findPadChunk(pad, startIndex, targetEntropyBits, options = {}) {
  const step = options.step || 64; // step size in bytes
  const padLen = pad.length;
  let s = ((startIndex % padLen) + padLen) % padLen;

  let winSize = step;
  while (winSize <= padLen && winSize <= 65536) { // cap at 64KB
    const windowBytes = new Uint8Array(winSize);
    for (let i = 0; i < winSize; i++) {
      windowBytes[i] = pad[(s + i) % padLen];
    }

    const entropyScore = await getChunkEntropy(windowBytes);
    const totalBits = entropyScore * 8 * winSize;

    if (totalBits >= targetEntropyBits) {
      return { chunk: windowBytes, nextIndex: (s + winSize) % padLen };
    }
    winSize += step;
  }

  // fallback: fixed 1KB chunk
  const fallbackSize = Math.min(padLen, 1024);
  const fallback = new Uint8Array(fallbackSize);
  for (let i = 0; i < fallbackSize; i++) fallback[i] = pad[(s + i) % padLen];
  return { chunk: fallback, nextIndex: (s + fallbackSize) % padLen };
}