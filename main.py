import subprocess
import hashlib
import os
import re
import sys

# ---------------- CONFIG ---------------- #

SUSPICIOUS_PATTERNS = re.compile(
    r"(https?://|/bin/sh|bash\s+-c|wget\s+http|curl\s+http|exec\(|eval\()",
    re.IGNORECASE
)

DANGEROUS_BINWALK_KEYWORDS = [
    "elf",
    "executable",
    "pe32",
    "zip",
    "rar",
    "7-zip",
    "script",
    "shell",
]

# heuristic weights
WEIGHTS = {
    "executable": 3,
    "clamav_fail": 6,
    "suspicious_strings": 2,
    "binary_claims_media": 4,
    "binwalk_confirmed_payload": 6,
    "binwalk_weak_signal": 1,
    "ffprobe_fail": 4,
    "unknown_streams": 3,
}

# ---------------- UTILS ---------------- #

def run(cmd):
    try:
        return subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        ).stdout.strip()
    except FileNotFoundError:
        return ""

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------- ANALYSIS ---------------- #

def analyze_strings(path):
    output = run(["strings", "-n", "8", path])
    return [l for l in output.splitlines() if SUSPICIOUS_PATTERNS.search(l)]

def clamav_scan(path):
    out = run(["clamscan", "--no-summary", path])
    return "OK" in out

def ffprobe_analysis(path):
    out = run(["ffprobe", "-v", "error", "-show_streams", path])
    if not out:
        return {"ok": False, "stream_count": 0, "unknown_streams": 0}

    streams = []
    for block in out.split("[STREAM]"):
        if "codec_type=" in block:
            streams.append(block)

    unknown = [
        s for s in streams
        if "codec_type=video" not in s and "codec_type=audio" not in s
    ]

    return {
        "ok": True,
        "stream_count": len(streams),
        "unknown_streams": len(unknown),
    }

def binwalk_analysis(path, size_bytes):
    out = run(["binwalk", path])
    hits = []

    for line in out.splitlines():
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue

        offset = int(parts[0])
        desc = line.lower()

        hits.append({
            "offset": offset,
            "description": line.strip(),
            "dangerous": any(k in desc for k in DANGEROUS_BINWALK_KEYWORDS),
            "near_start": offset < 1024 * 1024,
            "near_end": offset > size_bytes - (1024 * 1024),
        })

    return hits

# ---------------- MAIN LOGIC ---------------- #

def analyze_file(path):
    if not os.path.isfile(path):
        raise FileNotFoundError("File not found")

    result = {}
    score = 0

    size_bytes = os.path.getsize(path)

    result["file"] = path
    result["size_mb"] = round(size_bytes / (1024 * 1024), 2)
    result["sha256"] = sha256(path)
    result["type"] = run(["file", path])
    result["executable"] = os.access(path, os.X_OK)

    if result["executable"]:
        score += WEIGHTS["executable"]

    result["clamav_clean"] = clamav_scan(path)
    if not result["clamav_clean"]:
        score += WEIGHTS["clamav_fail"]

    suspicious_strings = analyze_strings(path)
    result["suspicious_strings"] = suspicious_strings
    if suspicious_strings:
        score += WEIGHTS["suspicious_strings"]

    ff = ffprobe_analysis(path)
    result["ffprobe"] = ff
    if not ff["ok"]:
        score += WEIGHTS["ffprobe_fail"]
    elif ff["unknown_streams"] > 0:
        score += WEIGHTS["unknown_streams"]

    binwalk_hits = binwalk_analysis(path, size_bytes)
    result["binwalk_hits"] = binwalk_hits

    confirmed_payload = False
    weak_signal = False

    for hit in binwalk_hits:
        if hit["dangerous"] and (hit["near_start"] or hit["near_end"]):
            confirmed_payload = True
        elif hit["dangerous"]:
            weak_signal = True

    # cross-validation
    if confirmed_payload and (suspicious_strings or not result["clamav_clean"]):
        score += WEIGHTS["binwalk_confirmed_payload"]
    elif weak_signal:
        score += WEIGHTS["binwalk_weak_signal"]

    if "video" in result["type"].lower() and result["size_mb"] < 50:
        score += WEIGHTS["binary_claims_media"]

    if score == 0:
        verdict = "LOW RISK"
    elif score <= 4:
        verdict = "MODERATE RISK"
    else:
        verdict = "HIGH RISK"

    result["risk_score"] = score
    result["verdict"] = verdict

    return result

# ---------------- ENTRYPOINT ---------------- #

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <file>")
        sys.exit(1)

    res = analyze_file(sys.argv[1])

    print("\n===== SECURITY DIAGNOSTIC =====\n")
    for k, v in res.items():
        if isinstance(v, list):
            print(f"{k}: {len(v)} occurrence(s)")
            for item in v[:5]:
                if isinstance(item, dict):
                    print(f"  -> {item['description']}")
                else:
                    print(f"  -> {item}")
        else:
            print(f"{k}: {v}")

    print("\nFinal verdict:", res["verdict"])
