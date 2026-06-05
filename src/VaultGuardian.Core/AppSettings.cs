namespace VaultGuardian.Core;

public sealed class AppSettings
{
    public int RefreshIntervalMs { get; set; } = 1000;
    public bool LaunchAtStartup { get; set; } = false;
    public bool ShowOverlayOnStart { get; set; } = true;
    public bool MinimizeToTrayOnClose { get; set; } = true;

    public event EventHandler? Changed;

    public void NotifyChanged() => Changed?.Invoke(this, EventArgs.Empty);
}
