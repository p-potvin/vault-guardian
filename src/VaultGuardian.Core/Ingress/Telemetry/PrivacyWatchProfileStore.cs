using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultGuardian.Core.Ingress.Telemetry;

public sealed class PrivacyWatchProfileStore
{
    private readonly string _path;

    public PrivacyWatchProfileStore(string path)
    {
        _path = path;
    }

    public async Task<PrivacyWatchProfile> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_path))
        {
            return PrivacyWatchProfile.Empty;
        }

        var json = await File.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false);
        var stored = JsonSerializer.Deserialize(json, PrivacyWatchProfileJsonContext.Default.StoredPrivacyWatchProfile);
        // A file containing `{}` deserializes to a non-null record whose Selectors
        // list is null; enumerating it directly would NRE.
        if (stored?.Selectors == null)
        {
            return PrivacyWatchProfile.Empty;
        }

        return new PrivacyWatchProfile(stored.Selectors
            .Select(selector => new PrivacySelector(
                selector.Label,
                selector.Kind,
                Unprotect(selector.ProtectedValue),
                selector.Enabled))
            .ToArray());
    }

    public async Task SaveAsync(PrivacyWatchProfile profile, CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var stored = new StoredPrivacyWatchProfile(profile.Selectors
            .Select(selector => new StoredPrivacySelector(
                selector.Label,
                selector.Kind,
                Protect(selector.Value),
                selector.Enabled))
            .ToArray());
        var json = JsonSerializer.Serialize(stored, PrivacyWatchProfileJsonContext.Default.StoredPrivacyWatchProfile);
        await File.WriteAllTextAsync(_path, json, cancellationToken).ConfigureAwait(false);
    }

    private static string Protect(string value)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI privacy profile protection requires Windows.");
        }

        var bytes = Encoding.UTF8.GetBytes(value);
        var protectedBytes = ProtectedData.Protect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(protectedBytes);
    }

    private static string Unprotect(string value)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI privacy profile protection requires Windows.");
        }

        var protectedBytes = Convert.FromBase64String(value);
        var bytes = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(bytes);
    }
}

public sealed record StoredPrivacyWatchProfile(IReadOnlyList<StoredPrivacySelector> Selectors);

public sealed record StoredPrivacySelector(
    string Label,
    PrivacySelectorKind Kind,
    string ProtectedValue,
    bool Enabled);

[JsonSerializable(typeof(StoredPrivacyWatchProfile))]
[JsonSourceGenerationOptions(WriteIndented = true, Converters = [typeof(JsonStringEnumConverter<PrivacySelectorKind>)])]
internal sealed partial class PrivacyWatchProfileJsonContext : JsonSerializerContext;
