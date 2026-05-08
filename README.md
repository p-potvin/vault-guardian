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
  blocking logic
- `tests/VaultGuardian.Core.Tests`: unit tests showing selective blocking (specific
  process + destination) versus default allow behavior
