namespace VaultGuardian.Core.Branding;

/// <summary>
/// Bilingual brand copy ported from vaultwares-themes/assets/brand.i18n.ts.
/// Console/Warm surfaces surface the same strings; language is selected via
/// <see cref="AppSettings.Language"/>. Supported codes: "en" and "fr-CA"
/// (mapped to the Québec "qc" variant, the house voice for French copy).
/// </summary>
public sealed record BrandStrings(
    string Tagline,
    string ExtendedTagline,
    string PrivacyNotice,
    string VaultSecured)
{
    private static readonly BrandStrings English = new(
        Tagline: "Privacy first. Security in service.",
        ExtendedTagline: "Privacy first. Security in service. Take back control of your digital footprint.",
        PrivacyNotice: "We do not track you. Here is what we store, and why.",
        VaultSecured: "Vault secured.");

    private static readonly BrandStrings Quebecois = new(
        Tagline: "La confidentialité d'abord. La sécurité au service.",
        ExtendedTagline: "La confidentialité d'abord. La sécurité au service. Des outils clairs pour tout le monde.",
        PrivacyNotice: "On ne vous suit pas. Voici ce que nous conservons, et pourquoi.",
        VaultSecured: "Encryption « Zero-Knowledge ».");

    /// <summary>
    /// Resolves the brand copy for a language code. Unknown codes fall back to
    /// English. "fr-CA" (and bare "fr") resolve to the Québec voice.
    /// </summary>
    public static BrandStrings For(string? language)
    {
        if (string.IsNullOrWhiteSpace(language))
        {
            return English;
        }

        return language.Trim().ToLowerInvariant() switch
        {
            "fr-ca" or "fr" or "qc" => Quebecois,
            _ => English,
        };
    }
}
