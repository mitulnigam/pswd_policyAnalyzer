# Password Policy Analyzer

A command-line tool that audits an organization's **password policy** against
modern industry standards — primarily [NIST SP 800-63B][nist] — rather than
scoring a single password. It reads a policy description, evaluates each
requirement, flags weaknesses, recommends concrete fixes, and explains *why*
each change matters with reference to breach data.

[nist]: https://pages.nist.gov/800-63-3/sp800-63b.html

## The problem it solves

Most password tools check whether *one password* is strong. But the real
security posture of a company is set by its **policy** — the rules every
employee's password must follow. Many organizations still run policies that
look strict but are actually outdated, and they don't realize it.

The twist this tool captures: modern guidance has **reversed** several old
"best practices." NIST SP 800-63B now advises *against* mandatory 90-day
rotation and forced special characters, because in practice they push users
toward predictable passwords (`Password1!`, `Spring2024` → `Summer2024`). A
good analyzer has to flag those as problems, not praise them — which is exactly
what separates an informed tool from a naive one.

## What it checks

| Control | Standard | Severity |
| --- | --- | --- |
| Minimum length (≥ 12 advised, 8 floor) | NIST §5.1.1.2 | Critical |
| Maximum length (≥ 64, no truncation) | NIST §5.1.1.2 | Medium |
| Composition / complexity rules | NIST §5.1.1.2 | Low |
| Periodic expiration | NIST §5.1.1.2 | Medium |
| Breached-password screening | NIST §5.1.1.2 | High |
| Multi-factor authentication | NIST §4 (AAL2) | Critical |
| Account lockout / rate limiting | NIST §5.2.2 | High |
| Password history / reuse | NIST §5.1.1.2 | Low |
| Paste / password-manager support | NIST §5.1.1.2 | Medium |
| Password hints / security questions | NIST §5.1.1.2 | Medium |

Each control is weighted by severity to produce a **0–100 score and a letter
grade**, so a non-technical stakeholder can see the headline result at a glance
while the analyst reads the detail.

## Usage

```bash
# audit a policy file
python3 password_policy_analyzer.py mypolicy.json

# try the included samples
python3 password_policy_analyzer.py samples/weak_policy.json
python3 password_policy_analyzer.py samples/strong_policy.json
```

## Policy file format

A policy is a small JSON file. Any field you omit falls back to a safe default,
so a partial file still gets a full audit.

```json
{
  "min_length": 14,
  "max_length": 0,
  "require_uppercase": false,
  "require_lowercase": false,
  "require_digit": false,
  "require_special": false,
  "expiration_days": 0,
  "history_count": 5,
  "lockout_threshold": 5,
  "screen_breached": true,
  "mfa_required": true,
  "allow_paste": true,
  "password_hints": false
}
```

(`max_length: 0` means "no stated maximum"; `expiration_days: 0` means
"no forced expiry".)

## Example output

Running the tool against `samples/weak_policy.json` — a typical outdated
corporate policy (short, complex, rotated every 90 days, no MFA). The report
opens with an at-a-glance summary, then lists issues worst-first with a Fix and
a Why, and ends with the passing controls and sources. In a terminal the
statuses and score are colour-coded (green / amber / red); colour is dropped
automatically when the output is piped to a file, or with `--no-color`.

```
==========================================================================
  PASSWORD POLICY AUDIT
  Policy:    weak_policy.json
  Benchmark: NIST SP 800-63B (Digital Identity Guidelines)
==========================================================================

  SCORE  22/100      GRADE  F
  #######-----------------------
  1 passed  ·  4 warnings  ·  5 failed

--------------------------------------------------------------------------
  ISSUES TO ADDRESS  (most serious first)
--------------------------------------------------------------------------

   FAIL  Minimum password length  (CRITICAL)
      Finding:   Minimum length is 6; below the 8-character floor.
      Fix:       Require at least 12 characters (NIST allows 8 as a hard
                 floor).
      Why:       Length is the single biggest factor in resisting offline
                 cracking; short passwords fall in seconds to modern GPUs.
                 Stolen credentials were the top initial action in
                 breaches, used in 24% of them (Verizon DBIR 2024).
      Reference: NIST SP 800-63B §5.1.1.2

   FAIL  Multi-factor authentication  (CRITICAL)
      Finding:   Multi-factor authentication is not required.
      Fix:       Require a second factor, preferably an authenticator app
                 or security key.
      Why:       MFA is the highest-leverage control against stolen
                 passwords. A Microsoft measurement study found it reduced
                 the risk of account compromise by 99.22% overall, and by
                 98.56% even for accounts whose passwords had already leaked.
      Reference: NIST SP 800-63B §4 (AAL2)

   ... (further issues) ...

--------------------------------------------------------------------------
  PASSING CONTROLS
--------------------------------------------------------------------------
  + Password history / reuse — Blocks reuse of the last 3 passwords.

--------------------------------------------------------------------------
  SOURCES  (statistics are year-stamped; verify before formal use)
--------------------------------------------------------------------------
  - Verizon 2024 Data Breach Investigations Report (DBIR)
    ...
==========================================================================
```

The same tool scores `samples/strong_policy.json` at **100/100 (A)**. The
`weak → 22` vs `strong → 100` contrast is the quickest way to demo it.

## How it works

1. **Load the policy** JSON and merge it over a set of safe defaults.
2. **Run each check** — a small function that returns `PASS`, `WARN`, or `FAIL`
   plus a one-line finding.
3. **Score it.** Each result earns credit (pass = full, warn = half, fail = 0)
   weighted by the control's severity, producing a 0–100 score and a grade.
4. **Report.** Passing controls are listed; anything less prints a `Fix` and a
   `Why` so the output doubles as a remediation plan.

## The breach statistics it cites

Each finding's rationale is backed by a real, sourced statistic rather than an
opinion — the point being to give a non-technical stakeholder a concrete reason
to act:

- **Stolen credentials were the top initial action in breaches, used in 24% of
  them** — Verizon 2024 Data Breach Investigations Report (DBIR).
- **MFA reduced the risk of account compromise by 99.22%** overall, and by
  98.56% even for accounts whose passwords had already leaked — Microsoft
  measurement study, *How effective is multifactor authentication at deterring
  cyberattacks?*
- **Public breach corpora such as Have I Been Pwned hold over 10 billion
  breached accounts** — the basis for screening new passwords against known
  leaks.

These figures are year-stamped because the reports are updated annually.
Verify the current numbers against the primary sources (listed at the end of
every report and in the tool itself) before quoting them in a formal document.

## Extending it

Good next steps: add checks for SMS-based MFA (now discouraged in favour of
authenticator apps or hardware keys), map each finding to a second framework
such as CIS Controls or PCI-DSS, or emit the report as JSON/HTML for a
dashboard.

## Requirements

- Python 3.6+. No third-party packages.

## Author

Built by Mitul Nigam as a hands-on cybersecurity project demonstrating
compliance auditing and the ability to communicate security findings to
non-technical stakeholders.
