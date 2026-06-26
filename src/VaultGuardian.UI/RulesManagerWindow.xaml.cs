using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using VaultGuardian.Core;
using VaultGuardian.Core.Firewall;
using Windows.UI;

namespace VaultGuardian.UI;

public sealed partial class RulesManagerWindow : Window
{
    private const string RulesFilePath = "rules.json";

    private readonly RuleDecisionEngine _engine;
    private readonly IFirewallRuleApplier _firewall;
    private readonly ILogger<RulesManagerWindow> _logger;

    public ObservableCollection<RuleRowVM> Rules { get; }

    public RulesManagerWindow(
        RuleDecisionEngine engine,
        IFirewallRuleApplier firewall,
        ILogger<RulesManagerWindow> logger)
    {
        _engine = engine;
        _firewall = firewall;
        _logger = logger;
        Rules = new ObservableCollection<RuleRowVM>(_engine.Rules.Select(RuleRowVM.From));

        InitializeComponent();
        Title = "Rule Manager";

        RulesList.ItemsSource = Rules;
    }

    public static string FormatAction(bool block) => block ? "BLOCK" : "ALLOW";

    public static Brush ActionBrush(bool block) =>
        new SolidColorBrush(block ? Color.FromArgb(0xFF, 0xFF, 0x6B, 0x7A) : Color.FromArgb(0xFF, 0x6B, 0xE6, 0x75));

    public static string FormatLifetime(bool isPersistent) => isPersistent ? "Persistent" : "Session";

    public static Brush LifetimeBrush(bool isPersistent) =>
        new SolidColorBrush(isPersistent ? Color.FromArgb(0xFF, 0xFF, 0xFF, 0xFF) : Color.FromArgb(0xFF, 0xA0, 0xA0, 0xA0));

    private async void OnAddRuleClick(object sender, RoutedEventArgs e)
    {
        await EditAsync(null, replacing: null);
    }

    private async void OnEditRuleClick(object sender, RoutedEventArgs e)
    {
        if (RulesList.SelectedItem is RuleRowVM selected)
        {
            await EditAsync(selected.Rule, replacing: selected);
        }
    }

    private async void OnRowDoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (RulesList.SelectedItem is RuleRowVM selected)
        {
            await EditAsync(selected.Rule, replacing: selected);
        }
    }

    private async Task EditAsync(EgressRule? existing, RuleRowVM? replacing)
    {
        if (Content is not FrameworkElement root) return;

        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var dialog = new RuleEditDialog(hwnd, existing) { XamlRoot = root.XamlRoot };

        var result = await dialog.ShowAsync();
        if (result != ContentDialogResult.Primary || dialog.Result == null) return;

        var row = RuleRowVM.From(dialog.Result);
        if (replacing != null)
        {
            var idx = Rules.IndexOf(replacing);
            if (idx >= 0) Rules[idx] = row;
        }
        else
        {
            Rules.Add(row);
        }

        await PersistAsync();
    }

    private async void OnRemoveRuleClick(object sender, RoutedEventArgs e)
    {
        if (RulesList.SelectedItem is RuleRowVM selected)
        {
            Rules.Remove(selected);
            await PersistAsync();
        }
    }

    private async Task PersistAsync()
    {
        var rules = Rules.Select(r => r.Rule).ToList();
        _engine.UpdateRules(rules);

        try
        {
            await RuleConfigurationLoader.SaveToFileAsync(RulesFilePath, rules);
        }
        catch (Exception ex)
        {
            await ShowErrorAsync($"Failed to save rules.json: {ex.Message}");
        }

        try
        {
            await _firewall.ApplyAsync(rules);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply firewall rules");
            await ShowErrorAsync(
                $"Rules saved, but applying them to Windows Firewall failed:\n{ex.Message}\n\nMake sure VaultGuardian is running as Administrator.");
        }
    }

    private async Task ShowErrorAsync(string message)
    {
        if (Content is not FrameworkElement root) return;
        var dlg = new ContentDialog
        {
            XamlRoot = root.XamlRoot,
            Title = "Error",
            Content = message,
            CloseButtonText = "OK",
        };
        await dlg.ShowAsync();
    }
}
