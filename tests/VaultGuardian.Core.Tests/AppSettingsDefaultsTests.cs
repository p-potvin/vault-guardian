using VaultGuardian.Core;

namespace VaultGuardian.Core.Tests;

public sealed class AppSettingsDefaultsTests
{
    [Fact]
    public void DefaultSettings_EnableBoundedIngressCapture()
    {
        var settings = new AppSettings();

        Assert.True(settings.EnableIngressPacketCapture);
    }
}
