/**
 * Privacy Bar
 * © 2026 Francisco Ruiz. All Rights Reserved.
 * * This source code is "Source-Available" for security auditing purposes only.
 * Redistribution, modification, or commercial use is strictly prohibited 
 * without explicit permission from the author.
 * * "Servers are Evil."
 */

/**
 * Core Crypto Utilities
 */

//Alphabets for base conversion. Used in making and reading the ezLock format
const base36 = "0123456789abcdefghijkLmnopqrstuvwxyz"; //capital L so it won't be mistaken for 1
const base64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function encodeBase64(arr) {
  if (typeof btoa === 'undefined') {
    return (new Buffer(arr)).toString('base64');
  } else {
    var i, s = [], len = arr.length;
    for (i = 0; i < len; i++) s.push(String.fromCharCode(arr[i]));
    return btoa(s.join('')).replace(/=/g, ''); //removed padding
  }
};

function decodeBase64(s) {
  if (typeof atob === 'undefined') {
    return new Uint8Array(Array.prototype.slice.call(new Buffer(s, 'base64'), 0));
  } else {
    try {															//added because atob may fail
      var i, d = atob(s), b = new Uint8Array(d.length);
    } catch (error) {
      return false
    }
    for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
    return b;
  }
};

//function to test key strength and come up with appropriate key stretching. Based on WiseHash
function keyStrength(string) {
  var entropy = entropyCalc(string),
    msg,
    colorName;

  if (entropy == 0) {
    msg = "This is a known bad Password!";
    colorName = "magenta";
  } else if (entropy < 20) {
    msg = "Terrible!";
    colorName = "magenta";
  } else if (entropy < 40) {
    msg = "Weak!";
    colorName = "red";
  } else if (entropy < 60) {
    msg = "Medium";
    colorName = "darkorange";
  } else if (entropy < 90) {
    msg = "Good!";
    colorName = "green";
  } else if (entropy < 120) {
    msg = "Great!";
    colorName = "blue";
  } else {
    msg = "Overkill  !!";
    colorName = "cyan";
  }

  var iter = Math.max(1, Math.min(20, Math.ceil(24 - entropy / 5))); //set the scrypt iteration exponent based on entropy: 1 for entropy >= 120, 20(max) for entropy <= 20

  return iter;
}

//takes a string and calculates its entropy in bits, taking into account the kinds of characters used and parts that may be in the general wordlist (reduced credit) or the blacklist (no credit)
function entropyCalc(string) {
  //find the raw Keyspace
  var numberRegex = new RegExp("^(?=.*[0-9]).*$", "g");
  var smallRegex = new RegExp("^(?=.*[a-z]).*$", "g");
  var capRegex = new RegExp("^(?=.*[A-Z]).*$", "g");
  var base64Regex = new RegExp("^(?=.*[/+]).*$", "g");
  var otherRegex = new RegExp("^(?=.*[^a-zA-Z0-9/+]).*$", "g");

  string = string.replace(/\s/g, ""); //no credit for spaces

  var Ncount = 0;
  if (numberRegex.test(string)) {
    Ncount = Ncount + 10;
  }
  if (smallRegex.test(string)) {
    Ncount = Ncount + 26;
  }
  if (capRegex.test(string)) {
    Ncount = Ncount + 26;
  }
  if (base64Regex.test(string)) {
    Ncount = Ncount + 2;
  }
  if (otherRegex.test(string)) {
    Ncount = Ncount + 31; //assume only printable characters
  }

  //start by finding words that might be on the blacklist (no credit)
  string = reduceVariants(string);
  var wordsFound = string.match(blackListExp); //array containing words found on the blacklist
  if (wordsFound) {
    for (var i = 0; i < wordsFound.length; i++) {
      string = string.replace(wordsFound[i], ""); //remove them from the string
    }
  }

  //now look for regular words on the wordlist
  wordsFound = string.match(wordListExp); //array containing words found on the regular wordlist
  if (wordsFound) {
    wordsFound = wordsFound.filter(function (elem, pos, self) {
      return self.indexOf(elem) == pos;
    }); //remove duplicates from the list
    var foundLength = wordsFound.length; //to give credit for words found we need to count how many
    for (var i = 0; i < wordsFound.length; i++) {
      string = string.replace(new RegExp(wordsFound[i], "g"), ""); //remove all instances
    }
  } else {
    var foundLength = 0;
  }

  string = string.replace(/(.+?)\1+/g, "$1"); //no credit for repeated consecutive character groups

  if (string != "") {
    return (
      (string.length * Math.log(Ncount) +
        foundLength * Math.log(wordLength + blackLength)) /
      Math.LN2
    );
  } else {
    return (foundLength * Math.log(wordLength + blackLength)) / Math.LN2;
  }
}

//take into account common substitutions, ignore spaces and case
function reduceVariants(string) {
  return string
    .toLowerCase()
    .replace(/[óòöôõo]/g, "0")
    .replace(/[!íìïîi]/g, "1")
    .replace(/[z]/g, "2")
    .replace(/[éèëêe]/g, "3")
    .replace(/[@áàäâãa]/g, "4")
    .replace(/[$s]/g, "5")
    .replace(/[t]/g, "7")
    .replace(/[b]/g, "8")
    .replace(/[g]/g, "9")
    .replace(/[úùüû]/g, "u");
}

const vowel = "aeiou";
const consonant = "bcdfghjklmnprstvwxyz";

//makes 'pronounceable' hash of a string, so user can be sure the password was entered correctly
function makeHashili(str) {
  const s = str.trim();
  if (!s) return "";

  const fullHash = nacl.hash(new TextEncoder().encode(s));
  const code = fullHash.slice(-2);
  let code10 = ((code[0] << 8) + code[1]) % 10000;

  let output = "";
  for (let i = 0; i < 2; i++) {
    const remainder = code10 % 100;
    output += consonant[Math.floor(remainder / 5)] + vowel[remainder % 5];
    code10 = Math.floor(code10 / 100);
  }
  return output; // e.g. "lomu"
}

//stretches a password string with a salt string to make a 256-bit Uint8Array Password
function wiseHash(string, salt, length) {
  var dkLen = length || 32,
    iter = keyStrength(string),
    secArray = new Uint8Array(dkLen),
    keyBytes;

  // Updated to the Options Object format
  scrypt(string, salt, {
    logN: iter, // Convert logN (e.g., 14) to literal N (16384)
    r: 8,
    p: 1,
    dkLen: dkLen
  }, function (x) {
    keyBytes = x;
  });

  // Assuming your library executes the callback synchronously
  for (var i = 0; i < dkLen; i++) {
    secArray[i] = keyBytes[i];
  }
  return secArray;
}

/**
 * ### SURGICAL EDIT: sha512Uint8
 * Uses the native Web Crypto API for high-performance SHA-512 hashing.
 * @param {Uint8Array} data - The input buffer to hash.
 * @returns {Promise<Uint8Array>} - The 64-byte SHA-512 digest.
 */
async function sha512Uint8(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-512', data);
  return new Uint8Array(hashBuffer);
}

//makes a full 24-byte nonce from a short nonce (e.g. 16 bytes). Returns Uint8Array
function makeNonce24(shortNonce) {
  // Standard helper to pad a short nonce to 24 bytes for NaCl
  const fullNonce = new Uint8Array(24);
  fullNonce.set(shortNonce);
  return fullNonce;
}

//makes the DH public string of a DH secret key array. Returns a base64 string
function makePub(sec) {
  return (pub = nacl.box.keyPair.fromSecretKey(sec).publicKey);
}

//Diffie-Hellman combination of a DH public key array and a DH secret key array. Returns Uint8Array
function makeShared(pub, sec) {
  return nacl.box.before(pub, sec);
}

//makes the DH public key (Montgomery) from a published Lock, which is a Signing public key (Edwards) in base36
function convertPubStr(Lock) {
  var LockBin = decodeBase64(changeBase(Lock, base36, base64, true));
  if (!LockBin) return false;
  return ed2curve.convertPublicKey(LockBin);
}

// Symmetric encryption with optional LZ compression
// Returns Uint8Array ciphertext
function symEncrypt(plainstr, nonce24, symKey, isCompressed) {
  let plain;

  // Skip compression if data contains embedded files (data URIs)
  if (!isCompressed || plainstr.match('="data:')) {
    plain = new TextEncoder().encode(plainstr);
  } else {
    plain = LZString.compressToUint8Array(plainstr);
  }

  return nacl.secretbox(plain, nonce24, symKey);
}

//concatenates multiple Uint8Arrays into one. Input: array of Uint8Arrays. Output: single Uint8Array
function concatUi8(arrays) {
  // Filter out any undefined/null entries to prevent NaN length errors
  const validArrays = arrays.filter(a => a && (a instanceof Uint8Array || Array.isArray(a)));
  
  let totalLength = validArrays.reduce((acc, value) => acc + value.length, 0);
  let result = new Uint8Array(totalLength);
  let length = 0;
  for (let array of validArrays) {
    result.set(array, length);
    length += array.length;
  }
  return result;
}

// Implements k-mode (Symmetric Encryption for storage)

/**
 * Binary Encryption with 9-byte Nonce
 * Saves 15 bytes of storage space per entry.
 */
function keyEncrypt(msgUint8, key) {
  // 1. Generate the "Short" 9-byte nonce
  const shortNonce = nacl.randomBytes(9);
  
  // 2. Pad to 24 bytes for NaCl (The remaining 15 bytes are 0 by default)
  const fullNonce = new Uint8Array(24);
  fullNonce.set(shortNonce);

  const box = nacl.secretbox(msgUint8, fullNonce, key);

  // 3. Assemble: [Marker 144][9b Nonce][Box]
  const fullMessage = new Uint8Array(1 + 9 + box.length);
  fullMessage[0] = 144;
  fullMessage.set(shortNonce, 1);
  fullMessage.set(box, 10);

  return encodeBase64(fullMessage);
}

/**
 * Binary Decryption with 9-byte Nonce
 */
function keyDecrypt(ciphertextBase64, key) {
  let fullMessage;
  try {
    fullMessage = decodeBase64(ciphertextBase64);
  } catch (e) { return null; }

  if (fullMessage[0] !== 144) return null;

  // 1. Extract the 9-byte nonce from storage
  const shortNonce = fullMessage.slice(1, 10);
  const box = fullMessage.slice(10);

  // 2. Reconstruct the 24-byte nonce for NaCl
  const fullNonce = new Uint8Array(24);
  fullNonce.set(shortNonce);

  return nacl.secretbox.open(box, fullNonce, key) || null;
}

//used both to encrypt and decrypt
async function prepareCommonData(masterPwd, myEmail) {
  // 1. Classic wiseHash (Strings in -> 32-byte Uint8Array out)
  const storageKey = wiseHash(masterPwd, myEmail);

  // 2. Derive Classic Ed25519 Keys
  const KeySgn = nacl.sign.keyPair.fromSeed(storageKey).secretKey;
  const myKey = ed2curve.convertSecretKey(KeySgn);
  const myLockbin = nacl.sign.keyPair.fromSecretKey(KeySgn).publicKey;

  // Use our tightened encoder to get the 50-char Base36 string
  const base36Lock = encodeUint8ToBase36(myLockbin);

  // 3. Derive PQ Keys (Only for ML-KEM)
  const pash64 = wiseHash(masterPwd, myEmail, 64);    //longer version of wiseHash
  const myPQPair = noblePostQuantum.ml_kem768.keygen(pash64);
  const mypqlockBase64 = encodeBase64(myPQPair.publicKey);

  // 4. The "Identity Check"
  // This validates the classic lock and updates BOTH if needed/accepted
  const isAuthorized = await validateAndUpdateMeLock(myEmail, base36Lock, currentHost, mypqlockBase64);

  if (!isAuthorized) {
    throw new Error("Master Key does not match the stored Identity.");
  }

  return {
    myKey,
    myLockbin,
    base36Lock,
    storageKey,
    myPQPair,
    mypqlockBase64
  };
}

/**
 * Modernized Base Converter using BigInt.
 * Handles padding for PassLok-specific lock lengths.
 */
function changeBase(numberIn, inAlpha, outAlpha, isLock) {
  const baseIn = BigInt(inAlpha.length);
  const baseOut = BigInt(outAlpha.length);
  let value = 0n;

  // 1. Convert input string to BigInt
  // We use for...of for cleaner iteration
  for (const char of numberIn) {
    const index = inAlpha.indexOf(char);
    if (index === -1) continue;
    value = value * baseIn + BigInt(index);
  }

  // 2. Short-circuit for zero
  if (value === 0n) return outAlpha[0].padStart(isLock ? (baseOut === 36n ? 50 : 43) : 1, outAlpha[0]);

  // 3. Convert BigInt to output string
  let result = "";
  while (value > 0n) {
    result = outAlpha[Number(value % baseOut)] + result;
    value /= baseOut;
  }

  // 4. Handle Lock padding using .padStart()
  if (isLock) {
    const lockLength = (baseOut === 36n) ? 50 : 43;   //32 bytes in base36 or base64
    return result.padStart(lockLength, outAlpha[0]);
  }

  return result;
}

// ---- Example Usage in sidepanel_passwords.js ----
function reportCryptoSuccess(mode, details) {
  let statusText = "";

  if (mode === "decrypt") {
    // If it's SIGNED and we have a sender, show both
    const modeStr = details.type || "Message";
    const senderStr = details.senderLock ? ` from ${details.senderLock}` : "";

    statusText += `Decrypted ${modeStr}${senderStr} (${details.length} chars)`;
  }
  else if (mode === "encrypt") {
    const recips = details.recipientCount > 0
      ? ` for ${details.recipientCount} recipient(s)`
      : "";
    statusText += `Encrypted ${details.mode}${recips}`;
  }
  showStatusMsg(statusText, "good");
}

// ---- PAD helpers for chunked SHA-512 / XOR mode ----
async function sha512Uint8(u8) {
  // accepts Uint8Array, returns Uint8Array(64)
  const buf = await crypto.subtle.digest('SHA-512', u8);
  return new Uint8Array(buf);
}

function xorUint8(a, b) {
  const n = Math.min(a.length, b.length);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = a[i] ^ b[i];
  return out;
}

//for display
function decodeBase36ToUint8(b36) {
  if (!b36 || !b36.trim()) return null;
  const b64 = changeBase(b36.trim(), base36, base64, true);
  return decodeBase64(b64);
}

function encodeUint8ToBase36(uint8) {
  const b64 = encodeBase64(uint8);
  return changeBase(b64, base64, base36, true);
}

// Helper: Uint8Array -> Latin-1 String
function binToLatin1(uint8) {
  let str = "";
  for (let i = 0; i < uint8.length; i++) {
    str += String.fromCharCode(uint8[i]);
  }
  return str;
}

// Helper: Latin-1 String -> Uint8Array
function latin1ToBin(str) {
  const buf = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    buf[i] = str.charCodeAt(i) & 0xFF;
  }
  return buf;
}

/**
 * Generates the 15-character PQ Fingerprint [hashili].
 * from PQ Lock
 */
function makePQPrint(pqlockBase64){
  if (!pqlockBase64) return "........";

  return changeBase(pqlockBase64.slice(0,12),base64,base36);
}