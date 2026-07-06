namespace VaultGuardian.Core;

public sealed class AppSettings
{
    public int RefreshIntervalMs { get; set; } = 1000;
    public bool LaunchAtStartup { get; set; } = false;
    public bool ShowOverlayOnStart { get; set; } = true;
    public bool MinimizeToTrayOnClose { get; set; } = true;
    public bool EnableIngressPacketCapture { get; set; } = true;

    /// <summary>
    /// Passively observe outbound TLS ClientHello (SNI) to learn hostnames for the
    /// non-MITM policy path. Metadata only — no TLS is terminated. Inbound DNS
    /// learning is always active with ingress capture.
    /// </summary>
    public bool EnableHostnameCorrelation { get; set; } = true;

    public bool EnableBrowserProfileMitm { get; set; } = false;
    public string MitmDumpPath { get; set; } = "mitmdump";
    public int MitmProxyPort { get; set; } = 18080;
    public string MitmBrowserExecutablePath { get; set; } = "msedge";

    /// <summary>
    /// UI copy language. Supported values: "en" (English) and "fr-CA" (Français, Québec).
    /// Drives the bilingual brand copy sourced from vaultwares-themes brand.i18n.
    /// </summary>
    public string Language { get; set; } = "en";

    public event EventHandler? Changed;

    public void NotifyChanged() => Changed?.Invoke(this, EventArgs.Empty);
}
