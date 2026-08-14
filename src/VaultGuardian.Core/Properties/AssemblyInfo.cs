using System.Runtime.CompilerServices;

// The WFP interop structs are internal on purpose — they are a P/Invoke detail,
// not public API — but their memory layout must be pinned by tests, since a
// wrong offset there fails silently at runtime rather than at compile time.
[assembly: InternalsVisibleTo("VaultGuardian.Core.Tests")]
