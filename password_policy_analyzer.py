#!/usr/bin/env python3
"""
Password Policy Analyzer
------------------------
Audits an organization's password policy against modern industry standards
(primarily NIST SP 800-63B) instead of just scoring a single password.

It reads a policy description (a JSON file), evaluates each requirement,
and produces a report that flags weaknesses, recommends concrete fixes, and
explains *why* each change matters with reference to breach data. The aim is
a tool a security analyst could hand to non-technical stakeholders.

Usage:
    python3 password_policy_analyzer.py <policy.json>
    python3 password_policy_analyzer.py samples/weak_policy.json
    python3 password_policy_analyzer.py --no-color samples/weak_policy.json
"""

import sys
import os
import json
import textwrap

# Status values a check can return, and how much credit each earns.
PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
CREDIT = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}

# Severity weights the overall score by how much each control matters.
SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Default policy assumptions. A real policy file overrides these; anything it
# omits falls back here so a short/partial file still produces a full audit.
POLICY_DEFAULTS = {
    "min_length": 0,
    "max_length": 0,            # 0 means "no stated maximum"
    "require_uppercase": False,
    "require_lowercase": False,
    "require_digit": False,
    "require_special": False,
    "expiration_days": 0,       # 0 means passwords never force-expire
    "history_count": 0,         # how many old passwords are remembered/blocked
    "lockout_threshold": 0,     # failed attempts before lockout; 0 means none
    "screen_breached": False,   # checks new passwords against breach corpora
    "mfa_required": False,
    "allow_paste": True,        # allowing paste supports password managers
    "password_hints": False,    # knowledge-based hints / security questions
}


# ---------------------------------------------------------------------------
# Individual checks. Each returns (status, detail): status is PASS/WARN/FAIL,
# detail is a one-line human-readable explanation of what was found.
# ---------------------------------------------------------------------------

def check_min_length(p):
    n = p["min_length"]
    if n < 8:
        return FAIL, f"Minimum length is {n}; below the 8-character floor."
    if n < 12:
        return WARN, f"Minimum length is {n}; meets the floor but 12+ is advised."
    return PASS, f"Minimum length is {n} characters."


def check_max_length(p):
    n = p["max_length"]
    if n == 0:
        return PASS, "No maximum length stated (passphrases allowed)."
    if n < 64:
        return FAIL, (f"Maximum length capped at {n}; blocks long passphrases "
                      f"and password-manager strings.")
    return PASS, f"Maximum length is {n} characters."


def check_composition(p):
    forced = sum([p["require_uppercase"], p["require_lowercase"],
                  p["require_digit"], p["require_special"]])
    if forced >= 3:
        return WARN, (f"Enforces {forced} composition rules; modern guidance "
                      f"drops these in favour of length + breach screening.")
    return PASS, "Does not over-rely on forced composition rules."


def check_expiration(p):
    d = p["expiration_days"]
    if d == 0:
        return PASS, "No forced periodic expiration."
    if d <= 365:
        return WARN, (f"Forces password change every {d} days; current guidance "
                      f"is to expire only on evidence of compromise.")
    return PASS, f"Expiration set to {d} days (effectively rare)."


def check_screen_breached(p):
    if not p["screen_breached"]:
        return FAIL, "New passwords are not screened against known-breached lists."
    return PASS, "New passwords are screened against breach corpora."


def check_mfa(p):
    if not p["mfa_required"]:
        return FAIL, "Multi-factor authentication is not required."
    return PASS, "Multi-factor authentication is required."


def check_lockout(p):
    t = p["lockout_threshold"]
    if t == 0:
        return FAIL, "No account lockout / rate-limiting on failed logins."
    if t > 10:
        return WARN, f"Lockout threshold is {t}; high enough to allow guessing."
    if t < 3:
        return WARN, f"Lockout threshold is {t}; low enough to enable easy lockout DoS."
    return PASS, f"Lockout after {t} failed attempts."


def check_history(p):
    h = p["history_count"]
    if h == 0:
        return WARN, "No password-history rule; immediate reuse is possible."
    return PASS, f"Blocks reuse of the last {h} passwords."


def check_allow_paste(p):
    if not p["allow_paste"]:
        return WARN, "Paste is blocked in password fields; discourages managers."
    return PASS, "Paste is allowed (supports password managers)."


def check_hints(p):
    if p["password_hints"]:
        return WARN, "Password hints / security questions are allowed."
    return PASS, "No password hints or knowledge-based recovery."


# ---------------------------------------------------------------------------
# Check registry. Each entry ties a check function to its severity, the
# standard it derives from, a fix, and the rationale (with breach context)
# shown when the check does not fully pass.
# ---------------------------------------------------------------------------
CHECKS = [
    {
        "id": "min-length",
        "title": "Minimum password length",
        "severity": "critical",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "fn": check_min_length,
        "fix": "Require at least 12 characters (NIST allows 8 as a hard floor).",
        "why": ("Length is the single biggest factor in resisting offline "
                "cracking; short passwords fall in seconds to modern GPUs. "
                "Stolen credentials were the top initial action in breaches, "
                "used in 24% of them (Verizon DBIR 2024)."),
    },
    {
        "id": "max-length",
        "title": "Maximum password length",
        "severity": "medium",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "fn": check_max_length,
        "fix": "Accept at least 64 characters; do not silently truncate.",
        "why": ("Low caps block passphrases and the long random strings that "
                "password managers generate, pushing users toward weaker, "
                "memorable passwords."),
    },
    {
        "id": "composition",
        "title": "Composition (complexity) rules",
        "severity": "low",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "fn": check_composition,
        "fix": ("Drop mandatory character-class rules; rely on length and "
                "breach screening instead."),
        "why": ("Forced complexity produces predictable patterns like "
                "'Password1!' and increases resets without adding real "
                "entropy. NIST now advises against mandating it. Note: some "
                "frameworks (e.g. PCI-DSS) still require it, so confirm your "
                "compliance obligations."),
    },
    {
        "id": "expiration",
        "title": "Periodic password expiration",
        "severity": "medium",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "fn": check_expiration,
        "fix": "Remove scheduled expiry; force a reset only on known compromise.",
        "why": ("Frequent forced rotation leads users to make minimal, "
                "guessable changes (Spring2024 -> Summer2024). NIST removed the "
                "periodic-change requirement for this reason."),
    },
    {
        "id": "breach-screening",
        "title": "Breached-password screening",
        "severity": "high",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "fn": check_screen_breached,
        "fix": ("Screen new passwords against a breach corpus such as "
                "Have I Been Pwned's Pwned Passwords (k-anonymity API)."),
        "why": ("Attackers reuse credentials leaked elsewhere (credential "
                "stuffing). Public breach corpora such as Have I Been Pwned "
                "hold over 10 billion breached accounts; blocking those "
                "passwords at the point of choice stops the most common "
                "automated attacks."),
    },
    {
        "id": "mfa",
        "title": "Multi-factor authentication",
        "severity": "critical",
        "reference": "NIST SP 800-63B §4 (AAL2)",
        "fn": check_mfa,
        "fix": "Require a second factor, preferably an authenticator app or security key.",
        "why": ("MFA is the highest-leverage control against stolen passwords. "
                "A Microsoft measurement study found it reduced the risk of "
                "account compromise by 99.22% overall, and by 98.56% even for "
                "accounts whose passwords had already leaked."),
    },
    {
        "id": "lockout",
        "title": "Account lockout / rate limiting",
        "severity": "high",
        "reference": "NIST SP 800-63B §5.2.2",
        "fn": check_lockout,
        "fix": "Throttle or lock after a small number of failed attempts (e.g. 5).",
        "why": ("Without rate limiting, attackers can brute-force or "
                "password-spray at will. NIST requires limiting consecutive "
                "failed attempts."),
    },
    {
        "id": "history",
        "title": "Password history / reuse",
        "severity": "low",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "fn": check_history,
        "fix": "Remember recent passwords to block immediate reuse.",
        "why": ("Preventing reuse stops users from cycling straight back to a "
                "compromised password after a reset."),
    },
    {
        "id": "allow-paste",
        "title": "Paste / password-manager support",
        "severity": "medium",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "fn": check_allow_paste,
        "fix": "Allow paste in password fields.",
        "why": ("Blocking paste frustrates password managers, which are one of "
                "the best tools for getting users onto strong, unique "
                "passwords."),
    },
    {
        "id": "hints",
        "title": "Password hints / knowledge-based recovery",
        "severity": "medium",
        "reference": "NIST SP 800-63B §5.1.1.2",
        "fn": check_hints,
        "fix": "Remove hints and security questions; use verified recovery channels.",
        "why": ("Hints and 'security questions' are often guessable or "
                "discoverable from social media, giving attackers an easy "
                "bypass of the password entirely."),
    },
]


# Primary sources for the statistics quoted in the rationale text. Figures are
# year-stamped because they are updated annually — verify before formal use.
SOURCES = [
    ("Verizon 2024 Data Breach Investigations Report (DBIR)",
     "https://www.verizon.com/business/resources/reports/dbir/"),
    ("Microsoft, 'How effective is multifactor authentication at deterring "
     "cyberattacks?'",
     "https://www.microsoft.com/en-us/research/publication/"
     "how-effective-is-multifactor-authentication-at-deterring-cyberattacks/"),
    ("Have I Been Pwned — Pwned Passwords",
     "https://haveibeenpwned.com/Passwords"),
    ("NIST SP 800-63B, Digital Identity Guidelines",
     "https://pages.nist.gov/800-63-3/sp800-63b.html"),
]


def load_policy(path):
    """Load a policy JSON file and merge it over the defaults."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    policy = dict(POLICY_DEFAULTS)
    policy.update(data)
    return policy, data


def grade(score):
    """Map a 0-100 score to a letter grade."""
    for cutoff, letter in [(90, "A"), (80, "B"), (70, "C"), (60, "D")]:
        if score >= cutoff:
            return letter
    return "F"


def analyze(policy):
    """Run every check and return a list of result rows plus the score."""
    results = []
    earned = 0.0
    possible = 0.0
    for check in CHECKS:
        status, detail = check["fn"](policy)
        weight = SEVERITY_WEIGHT[check["severity"]]
        earned += CREDIT[status] * weight
        possible += weight
        results.append({"check": check, "status": status, "detail": detail})
    score = round(100 * earned / possible) if possible else 0
    return results, score


WIDTH = 74
LABEL_COL = 11  # width of the wrapped "Finding:/Fix:/Why:" label column


class Palette:
    """ANSI colours, blanked out when colour is disabled so piped or
    redirected output stays clean plain text."""

    def __init__(self, enabled):
        codes = {
            "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
            "green": "\033[32m", "yellow": "\033[33m", "red": "\033[31m",
            "cyan": "\033[36m",
        }
        for name, code in codes.items():
            setattr(self, name, code if enabled else "")

    def paint(self, text, *styles):
        return "".join(styles) + text + self.reset if any(styles) else text


def colour_enabled(argv):
    """Enable colour only on a real terminal, unless overridden."""
    if "--no-color" in argv or "--no-colour" in argv:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")  # turn on ANSI escape handling on Windows 10+ terminals
    return True


def score_bar(score, pal, filled_len=30):
    """A simple [#####-----] bar, coloured by how healthy the score is."""
    filled = round(filled_len * score / 100)
    colour = pal.green if score >= 80 else pal.yellow if score >= 60 else pal.red
    bar = "#" * filled + "-" * (filled_len - filled)
    return pal.paint(bar, colour)


def wrap_field(label, text):
    """Wrap a long value under a fixed label column so every line aligns."""
    indent = " " * (6 + LABEL_COL)
    avail = WIDTH - len(indent)
    lines = textwrap.wrap(text, width=avail) or [""]
    out = [f"      {label:<{LABEL_COL}}{lines[0]}"]
    out.extend(indent + ln for ln in lines[1:])
    return "\n".join(out)


def print_report(policy_name, results, score, pal):
    status_colour = {PASS: pal.green, WARN: pal.yellow, FAIL: pal.red}
    status_label = {PASS: " PASS ", WARN: " WARN ", FAIL: " FAIL "}

    fails = sum(1 for r in results if r["status"] == FAIL)
    warns = sum(1 for r in results if r["status"] == WARN)
    passes = sum(1 for r in results if r["status"] == PASS)

    # ---- header + at-a-glance summary -------------------------------------
    bar = "=" * WIDTH
    print(bar)
    print(pal.paint("  PASSWORD POLICY AUDIT", pal.bold, pal.cyan))
    print(f"  Policy:    {policy_name}")
    print("  Benchmark: NIST SP 800-63B (Digital Identity Guidelines)")
    print(bar)

    grade_letter = grade(score)
    grade_colour = (pal.green if grade_letter in ("A", "B")
                    else pal.yellow if grade_letter in ("C", "D") else pal.red)
    print()
    print(f"  SCORE  {pal.paint(f'{score}/100', pal.bold, grade_colour)}"
          f"      GRADE  {pal.paint(grade_letter, pal.bold, grade_colour)}")
    print(f"  {score_bar(score, pal)}")
    print(f"  {pal.paint(str(passes) + ' passed', pal.green)}  ·  "
          f"{pal.paint(str(warns) + ' warnings', pal.yellow)}  ·  "
          f"{pal.paint(str(fails) + ' failed', pal.red)}")

    # ---- issues, worst first ----------------------------------------------
    rank = {FAIL: 0, WARN: 1}
    issues = [r for r in results if r["status"] != PASS]
    issues.sort(key=lambda r: (rank[r["status"]],
                               -SEVERITY_WEIGHT[r["check"]["severity"]]))

    if issues:
        print("\n" + "-" * WIDTH)
        print(pal.paint("  ISSUES TO ADDRESS", pal.bold) + "  (most serious first)")
        print("-" * WIDTH)
        for r in issues:
            c = r["check"]
            tag = pal.paint(status_label[r["status"]],
                            pal.bold, status_colour[r["status"]])
            print(f"\n  {tag} {pal.paint(c['title'], pal.bold)}  "
                  f"{pal.paint('(' + c['severity'].upper() + ')', pal.dim)}")
            print(wrap_field("Finding:", r["detail"]))
            print(wrap_field("Fix:", c["fix"]))
            print(wrap_field("Why:", c["why"]))
            print(wrap_field("Reference:", c["reference"]))

    # ---- passing controls, condensed --------------------------------------
    good = [r for r in results if r["status"] == PASS]
    if good:
        print("\n" + "-" * WIDTH)
        print(pal.paint("  PASSING CONTROLS", pal.bold))
        print("-" * WIDTH)
        for r in good:
            check_mark = pal.paint("+", pal.green)
            print(f"  {check_mark} {r['check']['title']} — {r['detail']}")

    # ---- sources ----------------------------------------------------------
    print("\n" + "-" * WIDTH)
    print(pal.paint("  SOURCES", pal.bold)
          + pal.paint("  (statistics are year-stamped; verify before formal use)",
                      pal.dim))
    print("-" * WIDTH)
    for name, url in SOURCES:
        print(f"  - {name}")
        print(f"    {pal.paint(url, pal.cyan)}")
    print(bar)


def main():
    argv = sys.argv[1:]
    pal = Palette(colour_enabled(argv))
    paths = [a for a in argv if not a.startswith("-")]

    if len(paths) != 1:
        print("Usage: python3 password_policy_analyzer.py [--no-color] <policy.json>")
        sys.exit(1)

    path = paths[0]
    if not os.path.isfile(path):
        print(f"[ERROR] '{path}' is not a file.")
        sys.exit(1)

    try:
        policy, _raw = load_policy(path)
    except json.JSONDecodeError as e:
        print(f"[ERROR] '{path}' is not valid JSON: {e}")
        sys.exit(1)

    results, score = analyze(policy)
    print_report(os.path.basename(path), results, score, pal)


if __name__ == "__main__":
    main()
