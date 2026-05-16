using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Collections.ObjectModel;
using VaultGuardian.Core;

namespace VaultGuardian.UI;

public partial class RulesManagerWindow : Window
{
    private readonly RuleDecisionEngine _engine;
    public ObservableCollection<EgressRule> Rules { get; }

    public RulesManagerWindow(RuleDecisionEngine engine)
    {
        _engine = engine;
        Rules = new ObservableCollection<EgressRule>(_engine.Rules);

        InitializeComponent();
        RulesList.ItemsSource = Rules;
    }

    private async void OnAddRuleClick(object sender, RoutedEventArgs e)
    {
        // Simple Add for now, would ideally open a dialog
        var newRule = new EgressRule(
            Name: $"Rule {Rules.Count + 1}",
            RemoteAddress: "0.0.0.0/0",
            Block: true);

        Rules.Add(newRule);
        _engine.UpdateRules(Rules);
        await RuleConfigurationLoader.SaveToFileAsync("rules.json", Rules);
    }

    private async void OnRemoveRuleClick(object sender, RoutedEventArgs e)
    {
        if (RulesList.SelectedItem is EgressRule selected)
        {
            Rules.Remove(selected);
            _engine.UpdateRules(Rules);
            await RuleConfigurationLoader.SaveToFileAsync("rules.json", Rules);
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
