using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Extensions.Logging;
using VaultGuardian.Core;
using VaultGuardian.Core.Firewall;

namespace VaultGuardian.UI;

public partial class RulesManagerWindow : Window
{
    private const string RulesFilePath = "rules.json";

    private readonly RuleDecisionEngine _engine;
    private readonly IFirewallRuleApplier _firewall;
    private readonly ILogger<RulesManagerWindow> _logger;

    public ObservableCollection<EgressRule> Rules { get; }

    public RulesManagerWindow(
        RuleDecisionEngine engine,
        IFirewallRuleApplier firewall,
        ILogger<RulesManagerWindow> logger)
    {
        _engine = engine;
        _firewall = firewall;
        _logger = logger;
        Rules = new ObservableCollection<EgressRule>(_engine.Rules);

        InitializeComponent();
        RulesList.ItemsSource = Rules;
    }

    private async void OnAddRuleClick(object sender, RoutedEventArgs e)
    {
        var dialog = new RuleEditDialog { Owner = this };
        if (dialog.ShowDialog() == true && dialog.Result != null)
        {
            Rules.Add(dialog.Result);
            await PersistAsync();
        }
    }

    private async void OnEditRuleClick(object sender, RoutedEventArgs e) => await EditSelectedAsync();

    private async void OnRulesListDoubleClick(object sender, MouseButtonEventArgs e) => await EditSelectedAsync();

    private async Task EditSelectedAsync()
    {
        if (RulesList.SelectedItem is not EgressRule selected) return;

        var dialog = new RuleEditDialog(selected) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.Result != null)
        {
            var index = Rules.IndexOf(selected);
            Rules[index] = dialog.Result;
            await PersistAsync();
        }
    }

    private async void OnRemoveRuleClick(object sender, RoutedEventArgs e)
    {
        if (RulesList.SelectedItem is EgressRule selected)
        {
            Rules.Remove(selected);
            await PersistAsync();
        }
    }

    private async Task PersistAsync()
    {
        _engine.UpdateRules(Rules);
        await RuleConfigurationLoader.SaveToFileAsync(RulesFilePath, Rules);

        try
        {
            await _firewall.ApplyAsync(Rules);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply firewall rules");
            MessageBox.Show(this,
                $"Rules saved, but applying them to Windows Firewall failed:\n{ex.Message}\n\nMake sure VaultGuardian is running as Administrator.",
                "Firewall Apply Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }
}

public class BlockToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => (bool)value ? "BLOCK" : "ALLOW";
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}

public class BlockToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => (bool)value ? Brushes.Red : Brushes.Green;
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}

public class PersistentToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => (bool)value ? "Persistent" : "Session";
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}

public class PersistentToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => (bool)value ? Brushes.White : new SolidColorBrush(Color.FromRgb(0xA0, 0xA0, 0xA0));
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}
