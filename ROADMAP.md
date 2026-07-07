# VaultGuardian Roadmap

_Last updated: Mon, 07 Jul 2026_

Scope and intent: VaultGuardian is a **single-user, local, privacy-first** Windows
tool for one home PC. It is not an enterprise NDR/EDR and should not adopt
enterprise cost or complexity. Every item below is weighed against "does this help
one person understand and control what their own machine is doing, at negligible
runtime cost?"

Current state is summarized in [README.md](README.md#current-state-v132). This file
is the forward plan.

---

## Priority 1 — WFP-native enforcement

Replace the WinDivert flow-layer interceptor with **Windows Filtering Platform**
filters as the primary enforcement path (WinDivert stays as a fallback where a
user cannot or will not load a third-party driver).

- User-mode WFP (`FwpmFilterAdd`/`FwpmEngineOpen`) for connect-time
  allow/deny keyed on app id + remote address/port; kernel callout only if
  per-packet mutation proves necessary.
- Motivation: WFP is the native, supported mechanism; it removes the third-party
  driver dependency and is what the mature comparables (simplewall, Portmaster)
  use. Aligns the code with the README's stated "WFP first" direction.

## Priority 2 — Free threat-intel matching (fingerprints + hosts)

Turn the JA4 fingerprint and hostname data from _displayed_ into _flagged_ by
matching against **free** feeds. This is where a single-PC tool actually gets
value out of fingerprinting — JA4's real strength (multi-device, high-volume
correlation) doesn't apply here, but "does this match a known-bad list?" does.

Decided sources (verify licences before shipping):

- **abuse.ch SSLBL + JA3 — approved.** Free JA3 fingerprints of malware C2, the
  most established free fingerprint feed. It is **JA3, not JA4**, so this requires
  computing **JA3 alongside JA4** (see deferred items). Worth adding.
- **ja4db.com (FoxIO) — wanted, with a twist.** Beyond malicious fingerprints,
  its value here is identifying **legit/popular apps that phone home** — i.e.
  known-good software emitting "telemetry"/data-collection traffic. Surfacing
  "this signed app is beaconing telemetry" is a privacy signal, not just a
  malware one. Check per-fingerprint licensing (JA4 core is BSD-3; some JA4+
  variants are licensed).
- **Host/IP blocklists — approved; effectively a local ad/malware blocker.**
  abuse.ch URLhaus / Feodo Tracker, StevenBlack hosts, the firebog lists, etc.
  Matching a process against known-bad/ad/telemetry **hosts** is the highest-value
  free signal for a home PC, and doing it in-app **removes the need to run an
  upstream AdGuard/Pi-hole** — VaultGuardian becomes the enforcement point.

Deliverable: a local, refreshable match engine (JA3/JA4 fingerprints + host
lists) that both flags triage/flow rows with the matched source and can block at
the firewall layer. No cloud calls beyond periodic feed download.

---

## Gate — 24/7 stability and overhead (must pass before Phase 3)

**Hard prerequisite:** before VaultGuardian logs behavior extensively, prove it
can run continuously without disrupting normal computer use. Extensive logging on
an app that isn't yet proven lightweight would both waste data and risk being the
very resource hog it's meant to catch.

Acceptance criteria (measure, don't assume):

- Runs unattended for a multi-day soak with no leaks (bounded memory, stable
  handle/thread counts) and no interception stalls.
- Negligible steady-state overhead under normal use (target: low single-digit
  CPU, modest RAM; capture/sniff loops stay bounded — the ingress capture limiter
  and hostname-map caps already exist and should be validated under load).
- No user-perceptible latency added to normal networking or app launches.
- The recent hot-path fix (non-throwing PID resolution via
  `ProcessImageResolver`) is representative of the bar: no exceptions on hot
  paths, no per-packet allocations that matter.

Instrumentation for this gate is in place: a persistent daily-rolling file log
(`<app>/logs/vaultguardian-*.log`) captures the full lifecycle (startup stages,
subsystem start/stop, shutdown) plus a **60-second heartbeat** recording our own
process working set / private bytes / thread & handle counts alongside traffic,
ingress, and hostname-map counters — the series to watch for leaks and drift over
a multi-day soak.

Only once this gate passes do we enable the behavioral logging in Phase 3.

---

## Priority 3 — Behavioral intelligence (after the gate)

Once the app is a trustworthy always-on resident, start accumulating behavior to
give better, context-aware advice. The value compounds with data.

- **Process behavior database.** Persist launches, terminations, resource
  patterns (RAM/CPU hogs), and side effects (e.g. a process that starts WSL /
  `vmmem` in the background). Local store, bounded, user-owned.
- **Contextual advice, not nagging.** Surface insight where the user already is —
  a quiet note, not a popup on every launch. Example: "You just launched X. You
  terminated it ~300 times last week — consider an alternative." Advice can also
  fire on _launch of a previously-problematic program_, or when a process repeats
  a pattern the user has repeatedly killed.
- **Behavior + reasoning capture.** Log not just events but the surrounding
  context and (optionally) the user's reasoning when they act, so future advice
  can explain _why_.
- **Model-ready scaffold.** Structure the data so a model could later be trained
  on it. Realistically thin with one user, but the schema/pipeline should exist so
  the option is open and multi-user is a future possibility, not a rewrite.

Privacy note: all of this is local and user-owned by default, consistent with the
app's "no cloud, no account" posture.

---

## Deferred hardening / smaller items

- **Privileged policy engine as a Windows service** with local IPC, splitting the
  firewall applier + interceptor out of the admin UI process. Real hardening, not
  MVP-blocking.
- **SNI/QUIC coverage beyond TCP 443** — the outbound SNI sniffer currently reads
  IPv4 TCP/443 only. Extend to IPv6 ClientHello capture and to QUIC (decrypt the
  QUIC Initial per RFC 9001 to recover the ClientHello / JA4Q), closing the
  HTTP/3 hostname blind spot. (Per-process attribution already handles IPv6 via
  AAAA-learned addresses.)
- **JA3 computation** — see Priority 2; needed to use the richer free JA3 feeds.
