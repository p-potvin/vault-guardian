using System.Text.Json;
using System.Text.Json.Serialization;
using VaultGuardian.Core;
using VaultGuardian.Core.Firewall;

namespace VaultGuardian.Core.Tests;

public sealed class AppSettingsDefaultsTests
{
    [Fact]
    public void DefaultSettings_EnableBoundedIngressCapture()
    {
        var settings = new AppSettings();

        Assert.True(settings.EnableIngressPacketCapture);
    }

    [Fact]
    public void DefaultSettings_PreferNativeWfpWithNetshFallback()
    {
        var settings = new AppSettings();

        Assert.Equal(FirewallBackend.Auto, settings.FirewallBackend);
    }

    [Fact]
    public void FirewallBackend_RoundTripsAsReadableNameInSettingsJson()
    {
        // Mirrors AppSettingsLoader's serializer configuration.
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() },
        };

        var json = JsonSerializer.Serialize(
            new AppSettings { FirewallBackend = FirewallBackend.Wfp }, options);

        Assert.Contains("\"Wfp\"", json);

        var restored = JsonSerializer.Deserialize<AppSettings>(json, options);
        Assert.Equal(FirewallBackend.Wfp, restored!.FirewallBackend);
    }
}
