# Ingress Telemetry, Full Trace, and Browser-Profile MITM Design

Updated: Mon, 29 Jun 2026 07:18

## Scope

Build the next ingress watcher layer around privacy telemetry detection and selective full tracing. The first active decryption path is a browser-profile MITM mode, because browser traffic is the most practical place to decrypt HTTPS while keeping the blast radius understandable and reversible.

This design does not attempt to silently decrypt arbitrary installed application traffic. Pinned apps, apps with private CA bundles, mTLS, or custom TLS stacks remain metadata-only unless a later per-app strategy is explicitly approved.

## Goals

- Detect incoming telemetry and personal-information exposure in plaintext, decrypted browser traffic, and metadata.
- Let a packet or flow trigger a bounded full trace that temporarily bypasses normal sampling limits for that source, flow, process, or browser profile.
- Add a browser-profile MITM workflow using the existing selective proxy direction.
- Keep all personal selectors and decrypted payloads local.
- Avoid logging secrets, selector values, decrypted bodies, or personal data into ledger entries, GitHub issues, docs, or console output.

## Non-Goals

- No transparent system-wide MITM in the first implementation.
- No bypassing certificate pinning.
- No stealth interception.
- No promise that encrypted app payloads are readable without key logs, a trusted proxy, or app cooperation.
- No long-running request generation for tests.

## Operating Modes

### Passive Baseline

The existing WinDivert watcher remains the base collector. It records source/process/protocol/ports, byte counts, timestamps, payload classification, and bounded payload samples. Encrypted traffic remains metadata-driven unless another mode produces plaintext.

Enhancements:
- Add telemetry-source tags for DNS/SNI/hostnames when available.
- Add TLS/QUIC metadata classifiers.
- Add privacy-hit summaries that reference selector labels, not selector values.

### Browser-Profile MITM Mode

VaultGuardian manages a local browser profile that is explicitly configured to use a local mitmproxy listener. The profile is separate from the user's normal browsing profile.

Workflow:
- Start/stop a local mitmproxy process from VaultGuardian.
- Create or reuse a dedicated browser profile directory.
- Launch supported browsers with that profile and proxy configuration.
- Detect whether the mitmproxy CA is trusted for that browser/profile.
- Ingest mitmproxy flow exports/events into the ingress store as decrypted HTTP observations.
- Apply the privacy selector engine to request/response headers and bodies.
- Allow passthrough rules for domains that break under MITM.

This mode is preferred over system-wide proxying for V1 because it is reversible, easier to test, and avoids breaking unrelated apps.

### Key-Log Assisted Mode

Keep this as a supporting mode after browser-profile MITM is in place. VaultGuardian can launch selected tools with TLS key logging enabled and preserve local key log files for trace decryption. This is useful for browsers or CLI tools that support NSS-style key log files, but it is not reliable for arbitrary installed apps.

## Privacy Watch Profile

The user configures a local privacy watch profile containing labeled selectors:
- Email addresses.
- Phone numbers.
- Names or aliases.
- Usernames.
- Domains owned by the user.
- Postal/address fragments.
- Device IDs or custom tokens.
- Custom regex rules.

Selector values are stored locally and are never included in logs, ledger entries, GitHub issues, or exported summaries unless the user explicitly exports the raw trace. UI hits show labels such as `email.primary` or `username.github`, not raw values.

## Detection Pipeline

1. Normalize each observation into an ingress content event.
2. Classify source: passive packet, decrypted MITM request, decrypted MITM response, or key-log decrypted trace.
3. Extract metadata: remote host, process/profile, protocol, method, path, status, content type, size, timestamp.
4. Run low-risk telemetry heuristics:
   - analytics/beacon-like paths,
   - small repeated POSTs,
   - tracking-looking hostnames,
   - device/app telemetry content types,
   - known browser profile source.
5. Run privacy selectors against plaintext/decrypted text and selected metadata fields.
6. Emit a `PrivacyTelemetryHit` with labels and confidence.
7. Evaluate full-trace trigger rules.

## Full Trace Triggers

Full trace is a temporary bypass over normal sampling, scoped by the trigger source.

Trigger examples:
- Privacy selector match.
- Decrypted browser request to telemetry-looking endpoint.
- Unknown inbound source with repeated encrypted traffic to a watched local process.
- Manual "Trace this flow/source/profile" UI action.

Trace bounds:
- Max duration.
- Max bytes.
- Max packets.
- Max per-source disk budget.
- Stop immediately when disk safety threshold is reached.

Trace output:
- A local trace bundle containing metadata, packet payload samples or raw bytes where available, decrypted MITM flow data where available, trigger reason labels, and timing information.
- Export is manual. Raw trace bundles are not automatically uploaded.

## Encrypted Traffic Handling

Passive encrypted traffic can still be useful:
- TLS/QUIC classification.
- Source and process attribution.
- Packet sizes and timing.
- SNI/hostnames only when visible.
- DNS correlation when available.
- Full trace trigger if metadata looks important.

Payload plaintext requires one of:
- Browser-profile MITM.
- Key-log assisted decryption.
- App-level cooperation.

If an app detects MITM or uses certificate pinning, VaultGuardian should mark it as `PinnedOrUninspectable`, add a passthrough rule if applicable, and continue metadata-only observation.

## UI

Add an Ingress "Telemetry" area using existing VaultWares theme tokens:
- Privacy hits list.
- Full trace active/idle status.
- Browser-profile MITM status: proxy off, proxy running, browser profile launched, CA trusted/untrusted, passthrough count.
- Trace controls: start manual trace, stop trace, export trace.
- Selector management entry point with labels visible and values hidden by default.

## Storage

Add local stores:
- Privacy watch profile.
- Telemetry hit archive.
- Full trace bundle index.
- MITM flow archive.

Encrypted/decrypted payload storage follows the existing archive safety model and full-trace bounds. Raw payloads are local-only and are cleared/exported manually.

## Testing

No live request loops are required.

Tests:
- Unit tests for selector matching with redacted hit output.
- Unit tests for full-trace trigger activation and bounded stop conditions.
- Unit tests for MITM flow import using fixture files, not live proxy traffic.
- Unit tests for pinned/uninspectable classification.
- UI contract tests for telemetry status and trace controls.
- Build verification with `dotnet test` and `dotnet build VaultGuardian.slnx`.
- Manual UI verification with a local fixture/import path first. Live mitmproxy browser-profile verification should be a separate explicit step.

## References

- Wireshark TLS decryption and key log files: https://wiki.wireshark.org/TLS
- TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
- QUIC TLS mapping: https://www.rfc-editor.org/rfc/rfc9001
- mitmproxy certificates: https://docs.mitmproxy.org/stable/concepts-certificates/
- mitmproxy modes: https://docs.mitmproxy.org/stable/concepts-modes/
- NIST TLS 1.3 visibility guidance: https://csrc.nist.gov/pubs/sp/1800/37/final

## Open Implementation Decisions

- Which browser is first-class for the profile launcher: Chrome, Edge, Firefox, or all Chromium-family browsers first.
- Whether mitmproxy is launched as a bundled dependency, user-installed dependency, or configurable executable path.
- Whether selector values are stored in a plain local JSON file initially or protected behind Windows DPAPI from the first implementation.
- Whether full trace bundles include raw packet bytes by default or require a second confirmation when privacy selectors match.
