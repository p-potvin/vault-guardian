# vault-guardian

Vault Guardian is a Windows-focused project to monitor outbound (egress) traffic
for selected apps/services and let users block suspicious communication.

## Chosen direction

- **UI:** WinUI 3
- **Packet/control engine:** WFP first, with WinDivert as a pragmatic fallback
  for interception workflows when needed.

## Feasibility research summary

Building this on Windows is possible. The main options are:

- **Windows Firewall APIs (`INetFw*`)**: easiest way to add/remove per-app or
  per-service block rules.
- **Windows Filtering Platform (WFP)**: native and powerful for deep filtering,
  but packet-level interception/modification requires kernel-mode callouts.
- **ETW (`Microsoft-Windows-TCPIP`)**: useful for passive monitoring and
  telemetry, but cannot block packets directly.
- **WinDivert**: user-mode friendly packet interception through a bundled
  signed driver (third-party dependency).

### Practical conclusion

- If the goal is **reliable app/service allow/deny with low complexity**:
  use Windows Firewall APIs first.
- If the goal is **deep per-packet interception before egress**:
  use WFP (native, higher complexity) or WinDivert (simpler integration,
  third-party driver).
- A **WinUI 3 app** is the most natural Windows-native UI choice.
- An **Electron app** is also possible, but still needs a privileged Windows
  native component (service/helper) for real filtering.

### Can we block specific requests, or only all-or-nothing?

It is **not all-or-nothing**. With WFP (and with WinDivert filtering logic), you
can block selectively using conditions like:

- process/service identity
- destination IP/port
- protocol and direction

Important nuance: this gives fine-grained control of **connections/flows/packets**.
For HTTPS, blocking a specific URL path requires TLS interception (MITM), which is
not part of this MVP.

### HTTPS MITM without trusted cert: possible?

Short answer: **no** (for normal secure clients).

To inspect HTTPS payload/URL path, a MITM proxy must terminate TLS and present a
certificate the client trusts. Without a trusted CA (OS or app trust store), the
TLS handshake fails or is warned/rejected. Some apps also use certificate
pinning, which can block MITM even when a local CA is trusted.

For this project's non-MITM path, policy should use metadata we can observe
without decrypting payloads, such as:

- process/service identity
- remote IP and port
- protocol and direction
- hostname metadata when available (for example from DNS/SNI correlation)

## Proposed architecture (minimal-risk path)

1. **UI layer (WinUI 3 or Electron)**  
   Displays monitored apps/services, traffic summaries, and block actions.
2. **Privileged policy engine**  
   Windows service that applies/removes firewall rules and exposes a local IPC
   API to the UI.
3. **Telemetry pipeline**  
   ETW/WFP event ingestion to correlate egress traffic with process/service.
4. **Decisioning**
   User selects trusted/untrusted apps; policy engine enforces block rules.

## MVP scope

- Select list of apps/services to watch.
- Show recent egress endpoints per selected process.
- One-click block/unblock via Windows Firewall rule management.
- Persist local policy and auditing logs.

## Initial implementation in this repository

The first code baseline is now in place:

- `src/VaultGuardian.Core`: rule model + decision engine for selective egress
  blocking logic (process + host/IP + port metadata)
- `tests/VaultGuardian.Core.Tests`: unit tests showing selective blocking (specific
  process + destination) versus default allow behavior

## Next build steps

1. Add policy ingestion from WFP/WinDivert telemetry adapters into the core
   decision engine (process + host/IP + port).
2. ✅ Build the first WinUI 3 shell (monitored apps view, recent egress, block/unblock).
3. ✅ Theming/branding integration using `p-potvin/vaultwares-themes`
   (`vaultwares-revisited` "Terminal and Document" system):
   - Warm document frame (parchment header/nav) wrapping the Console operational
     core, both coexisting per the source-of-truth philosophy — see
     `src/VaultGuardian.UI/Themes/VaultRedesign.xaml`.
   - Bilingual brand copy (English / Français QC) from `assets/brand.i18n.ts`,
     ported to `src/VaultGuardian.Core/Branding/BrandStrings.cs`, selectable in Settings.
   - Logo asset wired into the warm header (`Assets/vaultwares-logo.png`).

### Implemented since

- **DNS/SNI hostname correlation (non-MITM path).** Passive resolver under
  `src/VaultGuardian.Core/Ingress/Hostname/` parses DNS answers and TLS SNI to
  build a bounded, TTL-expiring address→hostname map. Two live feeds populate it:
  the ingress watcher ingests inbound DNS responses, and
  `WinDivertSniSniffer` passively sniffs outbound TLS ClientHello (port 443,
  RecvOnly — no traffic is blocked or decrypted) for SNI. The interceptor
  consults the resolver (via `IHostnameResolver`) to populate
  `TrafficObservation.RemoteHost`, so egress rules match on hostname without
  terminating TLS. Toggle: Settings → "Learn hostnames from DNS and TLS SNI".
- **JA4 TLS client fingerprinting.** `Ja4Calculator` computes the FoxIO JA4
  fingerprint from each ClientHello (transport + version + SNI flag + cipher/
  extension counts + ALPN, then truncated SHA-256 of sorted cipher suites and of
  sorted extensions with signature algorithms). The fingerprint identifies the
  client stack (browser/library/malware) independent of hostname or destination
  IP, and is recorded on each SNI-sourced resolution (`HostnameResolution.Ja4`).
- **Process triage console.** `WindowsProcessInspector` enumerates processes and
  fuses CPU sampling, image path / parent / hosted services (WMI), Authenticode
  trust, and the kernel critical-process bit into `ProcessFacts`;
  `ProcessTriageClassifier` (pure, unit-tested) tags each with a disposition
  (Legit/Unknown/Suspicious) and a kill-safety rating (Safe / Risky — disrupts
  services / Breaks Windows), with reasons. Surfaces svchost→service expansion
  and flags Hyper-V utility-VM aggregates (WSL2 `vmmem`) that hide their real
  consumers. The Processes pivot lists them by cost with a guarded Terminate
  (risk-scaled confirmation). Lets the operator act fast instead of retracing the
  tree in Process Explorer.
- **Per-process network attribution.** The inspector joins the active TCP tables
  (`GetExtendedTcpTable`, IPv4 and IPv6, owning PID → remote IPs) against the
  passive hostname/JA4 map, so each triage row surfaces the hostnames (and JA4 fingerprint) the
  process is actually talking to — e.g. an unsigned AppData process beaconing to
  a telemetry host. This fusion of resource cost + network reputation + signature
  trust is the signal a process-only tool can't give.

## Still open (post-MVP hardening)

- **WFP-native filtering** to replace WinDivert for environments that cannot
  ship a third-party driver.
- **Privileged policy engine as a Windows service** with local IPC, splitting
  the firewall applier + interceptor out of the admin UI process.
- **SNI coverage beyond port 443** (e.g. 8443, QUIC/HTTP-3) if non-standard TLS
  ports become relevant.
