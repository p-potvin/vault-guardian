using System.Windows;
using Microsoft.Win32;
using VaultGuardian.Core;

namespace VaultGuardian.UI;

public partial class RuleEditDialog : Window
{
    public EgressRule? Result { get; private set; }

    public RuleEditDialog() : this(null) { }

    public RuleEditDialog(EgressRule? existing)
    {
        InitializeComponent();
        if (existing != null) Populate(existing);
    }

    private void Populate(EgressRule rule)
    {
        NameBox.Text = rule.Name;
        ProcessPathBox.Text = rule.ProcessPath ?? string.Empty;
        RemoteAddressBox.Text = rule.RemoteAddress ?? string.Empty;
        RemoteHostBox.Text = rule.RemoteHost ?? string.Empty;
        RemotePortBox.Text = rule.RemotePort?.ToString() ?? string.Empty;
        ProtocolBox.SelectedIndex = rule.Protocol switch
        {
            TrafficProtocol.Tcp => 1,
            TrafficProtocol.Udp => 2,
            _ => 0,
        };
        BlockBox.IsChecked = rule.Block;
    }

    private void OnBrowseClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog() == true) ProcessPathBox.Text = dialog.FileName;
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        var name = NameBox.Text?.Trim();
        if (string.IsNullOrEmpty(name))
        {
            MessageBox.Show(this, "Name is required.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        int? port = null;
        var portText = RemotePortBox.Text?.Trim();
        if (!string.IsNullOrEmpty(portText))
        {
            if (!int.TryParse(portText, out var parsed) || parsed < 1 || parsed > 65535)
            {
                MessageBox.Show(this, "Port must be between 1 and 65535.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            port = parsed;
        }

        var protocol = ProtocolBox.SelectedIndex switch
        {
            1 => TrafficProtocol.Tcp,
            2 => TrafficProtocol.Udp,
            _ => TrafficProtocol.Any,
        };

        Result = new EgressRule(
            Name: name,
            ProcessPath: NullIfEmpty(ProcessPathBox.Text),
            RemoteHost: NullIfEmpty(RemoteHostBox.Text),
            RemoteAddress: NullIfEmpty(RemoteAddressBox.Text),
            RemotePort: port,
            Protocol: protocol,
            Block: BlockBox.IsChecked == true);

        DialogResult = true;
    }

    private static string? NullIfEmpty(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
