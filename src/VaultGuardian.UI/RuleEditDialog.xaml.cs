using System;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using VaultGuardian.Core;
using Windows.Storage.Pickers;

namespace VaultGuardian.UI;

public sealed partial class RuleEditDialog : ContentDialog
{
    public EgressRule? Result { get; private set; }
    private readonly IntPtr _ownerHwnd;

    public RuleEditDialog(IntPtr ownerHwnd, EgressRule? existing = null)
    {
        InitializeComponent();
        _ownerHwnd = ownerHwnd;

        if (existing != null)
        {
            NameBox.Text = existing.Name;
            ProcessBox.Text = existing.ProcessPath ?? string.Empty;
            AddressBox.Text = existing.RemoteAddress ?? string.Empty;
            HostBox.Text = existing.RemoteHost ?? string.Empty;
            PortBox.Text = existing.RemotePort?.ToString() ?? string.Empty;
            ProtocolBox.SelectedIndex = (int)existing.Protocol;
            BlockSwitch.IsOn = existing.Block;
        }

        PrimaryButtonClick += OnPrimaryClick;
    }

    private void OnPrimaryClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        ErrorText.Visibility = Visibility.Collapsed;

        var name = NameBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(name))
        {
            ShowError("Name is required.");
            args.Cancel = true;
            return;
        }

        int? port = null;
        var portText = PortBox.Text?.Trim();
        if (!string.IsNullOrWhiteSpace(portText))
        {
            if (!int.TryParse(portText, out var p) || p < 0 || p > 65535)
            {
                ShowError("Port must be an integer between 0 and 65535.");
                args.Cancel = true;
                return;
            }
            port = p;
        }

        var protocol = ProtocolBox.SelectedIndex switch
        {
            1 => TrafficProtocol.Tcp,
            2 => TrafficProtocol.Udp,
            _ => TrafficProtocol.Any,
        };

        Result = new EgressRule(
            Name: name!,
            ProcessPath: NullIfEmpty(ProcessBox.Text),
            RemoteHost: NullIfEmpty(HostBox.Text),
            RemoteAddress: NullIfEmpty(AddressBox.Text),
            RemotePort: port,
            Protocol: protocol,
            Block: BlockSwitch.IsOn);
    }

    private static string? NullIfEmpty(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }

    private async void OnBrowseClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker();
            WinRT.Interop.InitializeWithWindow.Initialize(picker, _ownerHwnd);
            picker.FileTypeFilter.Add(".exe");
            picker.FileTypeFilter.Add("*");
            picker.ViewMode = PickerViewMode.List;
            picker.SuggestedStartLocation = PickerLocationId.ComputerFolder;

            var file = await picker.PickSingleFileAsync();
            if (file != null)
            {
                ProcessBox.Text = file.Path;
            }
        }
        catch (Exception ex)
        {
            ShowError($"Could not open file picker: {ex.Message}");
        }
    }
}
