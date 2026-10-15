using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using VeilChat.Desktop.Core.Services;
using VeilChat.Desktop.Core.ViewModels;
using VeilChat.Desktop.Views;

namespace VeilChat.Desktop;

public sealed partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var previewSource = new MockConversationPreviewSource();
            var workerStatusService = new WorkerProcessService(
                WorkerProcessOptions.FromEnvironment(),
                new ProcessWorkerLauncher());
            var dataDirectory = Environment.GetEnvironmentVariable("VEIL_CHAT_DATA_DIRECTORY");
            if (string.IsNullOrWhiteSpace(dataDirectory) || !Path.IsPathFullyQualified(dataDirectory))
            {
                dataDirectory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VeilChat");
            }
            var accountService = new MatrixAccountService(
                workerStatusService,
                new SecureMatrixSessionStore(dataDirectory));
            var viewModel = new MainWindowViewModel(previewSource, workerStatusService, accountService);
            desktop.MainWindow = new MainWindow
            {
                DataContext = viewModel
            };
            desktop.MainWindow.Opened += async (_, _) => await viewModel.InitializeAsync();
            desktop.Exit += async (_, _) => await workerStatusService.DisposeAsync();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
