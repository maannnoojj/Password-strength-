import { useState, useEffect, useMemo, useCallback } from "react";
import { Eye, EyeOff, Check, X, ShieldCheck, RefreshCw, Copy, Trash2, Save, AlertTriangle } from "lucide-react";

// ---------- Palette / tokens ----------
const COLORS = {
  bg: "#0B0E14",
  panel: "#11151D",
  panelAlt: "#161B25",
  border: "#232A38",
  text: "#E4E7EC",
  textDim: "#8891A3",
  mono: "#5EEAD4",
  weak: "#EF4444",
  fair: "#F59E0B",
  good: "#EAB308",
  strong: "#4FD1C5",
  excellent: "#34D399",
};

const SCORE_META = [
  { label: "WEAK", color: COLORS.weak },
  { label: "FAIR", color: COLORS.fair },
  { label: "GOOD", color: COLORS.good },
  { label: "STRONG", color: COLORS.strong },
  { label: "EXCELLENT", color: COLORS.excellent },
];

const COMMON_PASSWORDS = new Set([
  "password", "123456", "123456789", "12345678", "12345", "qwerty",
  "abc123", "password1", "111111", "123123", "letmein", "welcome",
  "admin", "iloveyou", "monkey", "dragon", "sunshine", "princess",
  "football", "baseball", "trustno1", "qwerty123", "1q2w3e4r", "passw0rd",
  "starwars", "master", "hello", "freedom", "whatever", "qazwsx",
]);

const KEYBOARD_RUNS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

const WORDS = [
  "harbor", "lantern", "granite", "cobalt", "meadow", "ember", "quartz",
  "falcon", "willow", "canyon", "marble", "thistle", "ripple", "cedar",
  "opal", "juniper", "amber", "basil", "coral", "onyx",
];

// ---------- Pure analysis helpers ----------
function hasSequential(pw) {
  const lower = pw.toLowerCase();
  for (let i = 0; i < lower.length - 2; i++) {
    const a = lower.charCodeAt(i);
    const b = lower.charCodeAt(i + 1);
    const c = lower.charCodeAt(i + 2);
    if (b - a === 1 && c - b === 1) return true;
    if (a - b === 1 && b - c === 1) return true;
  }
  return false;
}

function hasRepeats(pw) {
  return /(.)\1\1/.test(pw);
}

function hasKeyboardRun(pw) {
  const lower = pw.toLowerCase();
  return KEYBOARD_RUNS.some((run) => {
    for (let i = 0; i <= run.length - 4; i++) {
      const chunk = run.slice(i, i + 4);
      if (lower.includes(chunk)) return true;
    }
    return false;
  });
}

function charsetSize(pw) {
  let size = 0;
  if (/[a-z]/.test(pw)) size += 26;
  if (/[A-Z]/.test(pw)) size += 26;
  if (/[0-9]/.test(pw)) size += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) size += 33;
  return size || 1;
}

function entropyBits(pw) {
  if (!pw) return 0;
  return Math.round(pw.length * Math.log2(charsetSize(pw)));
}

function crackTimeLabel(bits) {
  // Assume 10 billion guesses/sec (fast offline attack), average case = half the space
  const guessesPerSecond = 1e10;
  const combinations = Math.pow(2, bits);
  const seconds = combinations / guessesPerSecond / 2;

  if (seconds < 1) return "instantly";
  const units = [
    ["century", 60 * 60 * 24 * 365 * 100],
    ["year", 60 * 60 * 24 * 365],
    ["day", 60 * 60 * 24],
    ["hour", 60 * 60],
    ["minute", 60],
    ["second", 1],
  ];
  for (const [name, unitSeconds] of units) {
    const value = seconds / unitSeconds;
    if (value >= 1) {
      const rounded = value >= 100 ? Math.round(value).toLocaleString() : value.toFixed(1);
      return `~${rounded} ${name}${value >= 2 ? "s" : ""}`;
    }
  }
  return "instantly";
}

function analyze(pw) {
  const checks = {
    length: pw.length >= 12,
    minLength: pw.length >= 8,
    lower: /[a-z]/.test(pw),
    upper: /[A-Z]/.test(pw),
    digit: /[0-9]/.test(pw),
    symbol: /[^a-zA-Z0-9]/.test(pw),
    notCommon: !COMMON_PASSWORDS.has(pw.toLowerCase()),
    noRepeats: !hasRepeats(pw),
    noSequential: !hasSequential(pw) && !hasKeyboardRun(pw),
  };

  const bits = entropyBits(pw);

  let score = 0;
  if (pw.length > 0) {
    const variety = [checks.lower, checks.upper, checks.digit, checks.symbol].filter(Boolean).length;
    if (!checks.notCommon) {
      score = 0;
    } else {
      if (checks.minLength) score += 1;
      if (checks.length) score += 1;
      if (variety >= 3) score += 1;
      if (variety === 4) score += 1;
      if (checks.noRepeats && checks.noSequential && bits >= 60) score += 1;
      if (!checks.noRepeats || !checks.noSequential) score = Math.max(0, score - 1);
    }
  }
  score = Math.max(0, Math.min(4, score));

  return { checks, bits, score, crackTime: crackTimeLabel(bits) };
}

function randomChar(set) {
  return set[Math.floor(Math.random() * set.length)];
}

function generateStrongPassword(length = 16) {
  const lower = "abcdefghijkmnpqrstuvwxyz";
  const upper = "ABCDEFGHJKMNPQRSTUVWXYZ";
  const digits = "23456789";
  const symbols = "!@#$%^&*_-+=?";
  const all = lower + upper + digits + symbols;
  let pw = [randomChar(lower), randomChar(upper), randomChar(digits), randomChar(symbols)];
  for (let i = pw.length; i < length; i++) pw.push(randomChar(all));
  // shuffle
  for (let i = pw.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [pw[i], pw[j]] = [pw[j], pw[i]];
  }
  return pw.join("");
}

function generatePassphrase() {
  const picks = [];
  const used = new Set();
  while (picks.length < 3) {
    const w = WORDS[Math.floor(Math.random() * WORDS.length)];
    if (!used.has(w)) {
      used.add(w);
      picks.push(w.charAt(0).toUpperCase() + w.slice(1));
    }
  }
  const num = Math.floor(10 + Math.random() * 89);
  const symbol = randomChar("!@#$%*");
  return `${picks.join("-")}-${num}${symbol}`;
}

async function sha256Hex(text) {
  const enc = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------- UI subcomponents ----------
function CheckRow({ ok, children }) {
  return (
    <div className="flex items-center gap-2 text-sm py-1">
      {ok ? (
        <Check size={15} style={{ color: COLORS.excellent }} strokeWidth={3} />
      ) : (
        <X size={15} style={{ color: COLORS.textDim }} strokeWidth={3} />
      )}
      <span style={{ color: ok ? COLORS.text : COLORS.textDim }}>{children}</span>
    </div>
  );
}

function CopyButton({ value }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      setCopied(false);
    }
  };
  return (
    <button
      onClick={onCopy}
      className="flex items-center gap-1 text-xs px-2 py-1 rounded transition-colors"
      style={{ color: COLORS.textDim, border: `1px solid ${COLORS.border}` }}
      onMouseEnter={(e) => (e.currentTarget.style.color = COLORS.text)}
      onMouseLeave={(e) => (e.currentTarget.style.color = COLORS.textDim)}
    >
      <Copy size={12} />
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export default function PasswordStrengthAnalyzer() {
  const [pw, setPw] = useState("");
  const [visible, setVisible] = useState(false);
  const [history, setHistory] = useState([]);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const [reused, setReused] = useState(false);
  const [saveState, setSaveState] = useState("idle"); // idle | saving | saved | error
  const [suggestions, setSuggestions] = useState(null);
  const [storageError, setStorageError] = useState(false);

  const result = useMemo(() => analyze(pw), [pw]);
  const meta = SCORE_META[result.score];

  // Load history of hashed passwords once
  useEffect(() => {
    (async () => {
      try {
        const res = await window.storage.get("password-history", false);
        if (res && res.value) {
          setHistory(JSON.parse(res.value));
        }
      } catch (e) {
        // key not found is normal on first run
      } finally {
        setHistoryLoaded(true);
      }
    })();
  }, []);

  // Check reuse whenever password or history changes
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!pw) {
        setReused(false);
        return;
      }
      try {
        const hash = await sha256Hex(pw);
        if (!cancelled) setReused(history.includes(hash));
      } catch (e) {
        if (!cancelled) setReused(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [pw, history]);

  const saveToHistory = useCallback(async () => {
    if (!pw) return;
    setSaveState("saving");
    try {
      const hash = await sha256Hex(pw);
      const next = Array.from(new Set([...history, hash])).slice(-20);
      const result = await window.storage.set("password-history", JSON.stringify(next), false);
      if (!result) throw new Error("storage failed");
      setHistory(next);
      setSaveState("saved");
      setTimeout(() => setSaveState("idle"), 1500);
    } catch (e) {
      setSaveState("error");
      setStorageError(true);
      setTimeout(() => setSaveState("idle"), 2000);
    }
  }, [pw, history]);

  const clearHistory = useCallback(async () => {
    try {
      await window.storage.delete("password-history", false);
    } catch (e) {
      // ignore — key may not exist
    }
    setHistory([]);
  }, []);

  const handleSuggest = () => {
    setSuggestions({
      random: generateStrongPassword(16),
      passphrase: generatePassphrase(),
    });
  };

  const barSegments = [0, 1, 2, 3, 4];

  return (
    <div
      className="min-h-screen w-full flex items-start justify-center px-4 py-10"
      style={{ background: COLORS.bg, fontFamily: "'Inter', system-ui, sans-serif" }}
    >
      <div className="w-full max-w-xl">
        {/* Header */}
        <div className="mb-6">
          <div
            className="text-xs tracking-[0.3em] mb-2"
            style={{ color: COLORS.mono, fontFamily: "'JetBrains Mono', monospace" }}
          >
            CIPHER LAB // 01
          </div>
          <h1
            className="text-2xl font-semibold tracking-tight"
            style={{ color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }}
          >
            Password Strength Analyzer
          </h1>
          <p className="text-sm mt-1" style={{ color: COLORS.textDim }}>
            Type a password to see its estimated entropy, crack time, and reuse status. Nothing is sent anywhere — hashing happens in your browser.
          </p>
        </div>

        {/* Input panel */}
        <div
          className="rounded-lg p-5 mb-4"
          style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}` }}
        >
          <div
            className="flex items-center rounded-md px-3"
            style={{ background: COLORS.panelAlt, border: `1px solid ${COLORS.border}` }}
          >
            <input
              type={visible ? "text" : "password"}
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              placeholder="Enter a password to test"
              autoComplete="off"
              spellCheck={false}
              className="flex-1 bg-transparent outline-none py-3 text-base"
              style={{ color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }}
            />
            <button onClick={() => setVisible((v) => !v)} style={{ color: COLORS.textDim }} aria-label="Toggle visibility">
              {visible ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>

          {/* Strength meter */}
          <div className="mt-4">
            <div className="flex gap-1.5">
              {barSegments.map((i) => (
                <div
                  key={i}
                  className="h-1.5 flex-1 rounded-full transition-colors duration-300"
                  style={{
                    background: pw && i <= result.score ? meta.color : COLORS.border,
                  }}
                />
              ))}
            </div>
            <div className="flex items-center justify-between mt-2">
              <span
                className="text-xs font-semibold tracking-widest"
                style={{ color: pw ? meta.color : COLORS.textDim, fontFamily: "'JetBrains Mono', monospace" }}
              >
                {pw ? meta.label : "AWAITING INPUT"}
              </span>
              <span className="text-xs" style={{ color: COLORS.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
                {pw ? `${result.bits} bits · crack time ${result.crackTime}` : ""}
              </span>
            </div>
          </div>

          {reused && pw && (
            <div
              className="flex items-center gap-2 mt-3 text-xs rounded-md px-3 py-2"
              style={{ background: "rgba(239,68,68,0.1)", border: `1px solid ${COLORS.weak}`, color: COLORS.weak }}
            >
              <AlertTriangle size={14} />
              This matches a password you've saved to history before. Pick something new.
            </div>
          )}
        </div>

        {/* Breakdown */}
        <div
          className="rounded-lg p-5 mb-4"
          style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}` }}
        >
          <div className="text-xs tracking-widest mb-2" style={{ color: COLORS.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
            BREAKDOWN
          </div>
          <div className="grid grid-cols-2 gap-x-4">
            <CheckRow ok={result.checks.length}>12+ characters</CheckRow>
            <CheckRow ok={result.checks.upper}>Uppercase letter</CheckRow>
            <CheckRow ok={result.checks.lower}>Lowercase letter</CheckRow>
            <CheckRow ok={result.checks.digit}>Number</CheckRow>
            <CheckRow ok={result.checks.symbol}>Symbol</CheckRow>
            <CheckRow ok={result.checks.notCommon}>Not a common password</CheckRow>
            <CheckRow ok={result.checks.noRepeats}>No repeated characters (aaa)</CheckRow>
            <CheckRow ok={result.checks.noSequential}>No sequences (abc, 1234, qwerty)</CheckRow>
          </div>
        </div>

        {/* Reuse / history */}
        <div
          className="rounded-lg p-5 mb-4"
          style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}` }}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="text-xs tracking-widest" style={{ color: COLORS.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
              REUSE HISTORY ({history.length} SAVED)
            </div>
            {history.length > 0 && (
              <button onClick={clearHistory} className="flex items-center gap-1 text-xs" style={{ color: COLORS.textDim }}>
                <Trash2 size={12} /> Clear
              </button>
            )}
          </div>
          <p className="text-xs mb-3" style={{ color: COLORS.textDim }}>
            Only a SHA-256 hash of each password is stored — never the plaintext — so past passwords can be checked without keeping them readable.
          </p>
          <button
            onClick={saveToHistory}
            disabled={!pw || saveState === "saving"}
            className="flex items-center gap-2 text-xs px-3 py-2 rounded-md font-medium transition-opacity"
            style={{
              background: COLORS.mono,
              color: "#06201C",
              opacity: !pw ? 0.4 : 1,
            }}
          >
            <Save size={13} />
            {saveState === "saving" ? "Saving…" : saveState === "saved" ? "Saved" : saveState === "error" ? "Couldn't save" : "Save this password to history"}
          </button>
          {storageError && (
            <p className="text-xs mt-2" style={{ color: COLORS.weak }}>
              Storage isn't available right now — reuse checking will still work for this session.
            </p>
          )}
        </div>

        {/* Suggestions */}
        <div
          className="rounded-lg p-5"
          style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}` }}
        >
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs tracking-widest" style={{ color: COLORS.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
              STRONGER ALTERNATIVES
            </div>
            <button
              onClick={handleSuggest}
              className="flex items-center gap-1 text-xs px-2 py-1 rounded"
              style={{ color: COLORS.strong, border: `1px solid ${COLORS.border}` }}
            >
              <RefreshCw size={12} /> Generate
            </button>
          </div>

          {!suggestions && (
            <p className="text-xs" style={{ color: COLORS.textDim }}>
              Generate a random high-entropy password or a memorable passphrase.
            </p>
          )}

          {suggestions && (
            <div className="flex flex-col gap-2">
              <div
                className="flex items-center justify-between rounded-md px-3 py-2"
                style={{ background: COLORS.panelAlt, border: `1px solid ${COLORS.border}` }}
              >
                <span style={{ color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }} className="text-sm break-all">
                  {suggestions.random}
                </span>
                <CopyButton value={suggestions.random} />
              </div>
              <div
                className="flex items-center justify-between rounded-md px-3 py-2"
                style={{ background: COLORS.panelAlt, border: `1px solid ${COLORS.border}` }}
              >
                <span style={{ color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }} className="text-sm break-all">
                  {suggestions.passphrase}
                </span>
                <CopyButton value={suggestions.passphrase} />
              </div>
              <p className="text-xs mt-1" style={{ color: COLORS.textDim }}>
                The random string packs more entropy per character; the passphrase trades a little entropy for something you can actually remember.
              </p>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 mt-6 justify-center">
          <ShieldCheck size={14} style={{ color: COLORS.textDim }} />
          <span className="text-xs" style={{ color: COLORS.textDim }}>
            Everything above runs locally in your browser.
          </span>
        </div>
      </div>
    </div>
  );
}
