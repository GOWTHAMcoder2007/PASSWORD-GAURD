/* =========================================================
   Password Strength Checker — script.js
   100% client-side. Nothing here ever sends, stores, or
   logs the raw password. All analysis happens in memory
   only, for as long as the page is open.
   ========================================================= */

(function () {
  "use strict";

  /* ---------------- Element references ---------------- */
  const passwordInput   = document.getElementById("passwordInput");
  const toggleVisibility = document.getElementById("toggleVisibility");
  const clearBtn         = document.getElementById("clearBtn");

  const meterFill      = document.getElementById("meterFill");
  const meterTrack     = document.getElementById("meterTrack");
  const strengthLabel  = document.getElementById("strengthLabel");
  const scoreText      = document.getElementById("scoreText");

  const checklistEl    = document.getElementById("checklist");
  const suggestionsEl  = document.getElementById("suggestions");

  const lengthRange     = document.getElementById("lengthRange");
  const lengthValue     = document.getElementById("lengthValue");
  const optUpper        = document.getElementById("optUpper");
  const optLower        = document.getElementById("optLower");
  const optNumbers      = document.getElementById("optNumbers");
  const optSpecial      = document.getElementById("optSpecial");
  const generateBtn     = document.getElementById("generateBtn");
  const generatedOutput = document.getElementById("generatedOutput");
  const copyBtn         = document.getElementById("copyBtn");
  const copyStatus      = document.getElementById("copyStatus");
  const useGeneratedBtn = document.getElementById("useGeneratedBtn");

  /* ---------------- Reference data ---------------- */

  // A short list of very common / breached passwords.
  // Checked in lowercase, so case does not help these.
  const COMMON_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "letmein", "admin", "welcome",
    "iloveyou", "monkey", "dragon", "football", "abc123",
    "password1", "password123", "sunshine", "princess", "master",
    "login", "starwars", "trustno1", "111111", "123123",
    "000000", "1q2w3e4r", "passw0rd", "admin123", "changeme",
    "qazwsx", "asdfgh", "zxcvbn", "welcome1", "michael",
    "shadow", "superman", "batman", "freedom", "whatever"
  ];

  const SEQUENCE_FRAGMENTS = [
    "0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop",
    "asdfghjkl", "zxcvbnm"
  ];

  const UPPER_CHARS   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const LOWER_CHARS   = "abcdefghijklmnopqrstuvwxyz";
  const NUMBER_CHARS  = "0123456789";
  const SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  /* ---------------- Analysis helpers ---------------- */

  function hasUpper(pw)   { return /[A-Z]/.test(pw); }
  function hasLower(pw)   { return /[a-z]/.test(pw); }
  function hasNumber(pw)  { return /[0-9]/.test(pw); }
  function hasSpecial(pw) { return /[^A-Za-z0-9]/.test(pw); }

  function isCommonPassword(pw) {
    const lower = pw.toLowerCase();
    return COMMON_PASSWORDS.indexOf(lower) !== -1;
  }

  // Detects 4+ character runs that are either an ascending/
  // descending numeric or alphabetic sequence (e.g. "1234",
  // "4321", "abcd", "dcba"), or a keyboard-row fragment
  // (e.g. "qwerty", "asdf").
  function hasSequentialPattern(pw) {
    const lower = pw.toLowerCase();

    // Keyboard / alphabet / digit fragments (length 4+ substrings)
    for (const frag of SEQUENCE_FRAGMENTS) {
      for (let i = 0; i <= frag.length - 4; i++) {
        const forward = frag.substring(i, i + 4);
        const backward = forward.split("").reverse().join("");
        if (lower.includes(forward) || lower.includes(backward)) {
          return true;
        }
      }
    }

    // Generic ascending/descending run of consecutive char codes
    let ascRun = 1;
    let descRun = 1;
    for (let i = 1; i < lower.length; i++) {
      const prev = lower.charCodeAt(i - 1);
      const curr = lower.charCodeAt(i);

      if (curr === prev + 1) {
        ascRun++;
        descRun = 1;
      } else if (curr === prev - 1) {
        descRun++;
        ascRun = 1;
      } else {
        ascRun = 1;
        descRun = 1;
      }

      if (ascRun >= 4 || descRun >= 4) {
        return true;
      }
    }

    return false;
  }

  // Flags 3 or more of the exact same character in a row,
  // e.g. "aaa", "111".
  function hasExcessiveRepetition(pw) {
    return /(.)\1{2,}/.test(pw);
  }

  function evaluatePassword(pw) {
    const checks = {
      len8:      pw.length >= 8,
      len12:     pw.length >= 12,
      upper:     hasUpper(pw),
      lower:     hasLower(pw),
      number:    hasNumber(pw),
      special:   hasSpecial(pw),
      common:    pw.length > 0 && !isCommonPassword(pw),
      sequence:  pw.length > 0 && !hasSequentialPattern(pw),
      repetition: pw.length > 0 && !hasExcessiveRepetition(pw)
    };

    // Weighted scoring — weights sum to 100.
    const WEIGHTS = {
      len8: 10, len12: 15, upper: 10, lower: 10, number: 10,
      special: 15, common: 10, sequence: 10, repetition: 10
    };

    let score = 0;
    if (pw.length > 0) {
      for (const key in WEIGHTS) {
        if (checks[key]) score += WEIGHTS[key];
      }
    }

    // Extra penalty: a known common password is dangerous even
    // if it happens to be long, so cap the score hard.
    if (pw.length > 0 && isCommonPassword(pw)) {
      score = Math.min(score, 15);
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    let strength;
    if (pw.length === 0)      strength = "none";
    else if (score < 30)      strength = "very-weak";
    else if (score < 50)      strength = "weak";
    else if (score < 70)      strength = "medium";
    else if (score < 90)      strength = "strong";
    else                      strength = "very-strong";

    return { checks, score, strength };
  }

  const STRENGTH_META = {
    "none":        { label: "—",           color: "var(--text-muted)", css: "" },
    "very-weak":   { label: "Very Weak",   color: "var(--danger)",     css: "strength-very-weak" },
    "weak":        { label: "Weak",        color: "var(--warning)",    css: "strength-weak" },
    "medium":      { label: "Medium",      color: "var(--caution)",    css: "strength-medium" },
    "strong":      { label: "Strong",      color: "var(--good)",       css: "strength-strong" },
    "very-strong": { label: "Very Strong", color: "var(--great)",      css: "strength-very-strong" }
  };

  function buildSuggestions(pw, checks) {
    const tips = [];

    if (pw.length === 0) {
      return ["Start typing a password to see suggestions."];
    }
    if (!checks.len12) tips.push("Use at least 12 characters.");
    if (!checks.upper || !checks.lower) tips.push("Add both uppercase and lowercase letters.");
    if (!checks.number) tips.push("Add at least one number.");
    if (!checks.special) tips.push("Add at least one special character (e.g. ! @ # $).");
    if (!checks.common) tips.push("Avoid common or breached passwords.");
    if (!checks.sequence) tips.push("Avoid obvious sequences like 1234, abcd, or qwerty.");
    if (!checks.repetition) tips.push("Avoid repeating the same character many times in a row.");

    if (tips.length === 0) {
      tips.push("Great job! This password meets all the checks.");
    }
    return tips;
  }

  /* ---------------- UI update ---------------- */

  function updateUI() {
    const pw = passwordInput.value; // read once, never logged, never stored
    const { checks, score, strength } = evaluatePassword(pw);
    const meta = STRENGTH_META[strength];

    // Score + label
    scoreText.textContent = "Score: " + score + "/100";
    strengthLabel.textContent = meta.label;
    strengthLabel.className = "strength-label " + meta.css;

    // Meter
    meterFill.style.width = score + "%";
    meterFill.style.backgroundColor = meta.color;
    meterTrack.setAttribute("aria-valuenow", String(score));

    // Checklist
    const items = checklistEl.querySelectorAll("li[data-check]");
    items.forEach((li) => {
      const key = li.getAttribute("data-check");
      const passed = pw.length > 0 && checks[key];
      li.classList.toggle("passed", passed);
      const icon = li.querySelector(".check-icon");
      icon.textContent = passed ? "✓" : "✗";
    });

    // Suggestions
    const tips = buildSuggestions(pw, checks);
    suggestionsEl.innerHTML = "";
    tips.forEach((tip) => {
      const li = document.createElement("li");
      li.textContent = tip;
      suggestionsEl.appendChild(li);
    });
  }

  /* ---------------- Show / hide / clear ---------------- */

  function toggleShowHide() {
    const isPassword = passwordInput.type === "password";
    passwordInput.type = isPassword ? "text" : "password";
    toggleVisibility.textContent = isPassword ? "🙈" : "👁";
    toggleVisibility.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
    toggleVisibility.setAttribute("aria-pressed", String(isPassword));
  }

  function clearPassword() {
    passwordInput.value = "";
    passwordInput.focus();
    updateUI();
  }

  /* ---------------- Password generator ---------------- */

  // Uses crypto.getRandomValues for cryptographically strong
  // randomness instead of Math.random().
  function secureRandomInt(maxExclusive) {
    const range = maxExclusive;
    const maxUint32 = 0xFFFFFFFF;
    const limit = maxUint32 - (maxUint32 % range);
    const arr = new Uint32Array(1);

    let value;
    do {
      crypto.getRandomValues(arr);
      value = arr[0];
    } while (value > limit);

    return value % range;
  }

  function secureShuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  function generatePassword(length, useUpper, useLower, useNumbers, useSpecial) {
    const pools = [];
    if (useUpper)   pools.push(UPPER_CHARS);
    if (useLower)   pools.push(LOWER_CHARS);
    if (useNumbers) pools.push(NUMBER_CHARS);
    if (useSpecial) pools.push(SPECIAL_CHARS);

    if (pools.length === 0) {
      // Fallback so the generator never silently fails.
      pools.push(LOWER_CHARS);
    }

    const allChars = pools.join("");
    const passwordChars = [];

    // Guarantee at least one character from each selected pool.
    pools.forEach((pool) => {
      passwordChars.push(pool[secureRandomInt(pool.length)]);
    });

    // Fill the rest randomly from the combined pool.
    while (passwordChars.length < length) {
      passwordChars.push(allChars[secureRandomInt(allChars.length)]);
    }

    // Trim in case guaranteed chars exceeded requested length
    // (only possible if length < number of selected pools).
    const trimmed = passwordChars.slice(0, Math.max(length, pools.length));

    return secureShuffle(trimmed).join("");
  }

  function handleGenerateClick() {
    const length = parseInt(lengthRange.value, 10);
    const useUpper   = optUpper.checked;
    const useLower   = optLower.checked;
    const useNumbers = optNumbers.checked;
    const useSpecial = optSpecial.checked;

    const generated = generatePassword(length, useUpper, useLower, useNumbers, useSpecial);
    generatedOutput.value = generated; // held only in the DOM/memory, never persisted
    copyStatus.textContent = "";
  }

  async function handleCopyClick() {
    const value = generatedOutput.value;
    if (!value) {
      copyStatus.textContent = "Generate a password first.";
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      copyStatus.textContent = "Copied to clipboard!";
    } catch (err) {
      // Fallback for environments without Clipboard API access.
      generatedOutput.select();
      document.execCommand("copy");
      copyStatus.textContent = "Copied to clipboard!";
    }
    setTimeout(() => { copyStatus.textContent = ""; }, 2500);
  }

  function handleUseGenerated() {
    if (!generatedOutput.value) return;
    passwordInput.value = generatedOutput.value;
    updateUI();
    passwordInput.focus();
  }

  /* ---------------- Event wiring ---------------- */

  passwordInput.addEventListener("input", updateUI);
  toggleVisibility.addEventListener("click", toggleShowHide);
  clearBtn.addEventListener("click", clearPassword);

  lengthRange.addEventListener("input", () => {
    lengthValue.textContent = lengthRange.value;
  });

  generateBtn.addEventListener("click", handleGenerateClick);
  copyBtn.addEventListener("click", handleCopyClick);
  useGeneratedBtn.addEventListener("click", handleUseGenerated);

  /* ---------------- Init ---------------- */

  updateUI();
})();
