using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VeilChat.Desktop.Core.Services;

namespace VeilChat.Desktop.Core.ViewModels;

public sealed class MainWindowViewModel : ObservableObject
{
    private object _currentPage;
    private string _activeNavigation = "Chats";

    public ChatsPageViewModel ChatsPage { get; }

    public SettingsPageViewModel SettingsPage { get; }

    public object CurrentPage
    {
        get => _currentPage;
        private set => SetProperty(ref _currentPage, value);
    }

    public string ActiveNavigation
    {
        get => _activeNavigation;
        private set => SetProperty(ref _activeNavigation, value);
    }

    public IRelayCommand ShowChatsCommand { get; }

    public IAsyncRelayCommand ShowSettingsCommand { get; }

    public MainWindowViewModel(
        IConversationPreviewSource previewSource,
        IWorkerStatusService workerStatusService,
        MatrixAccountService? accountService = null)
    {
        ChatsPage = new ChatsPageViewModel(previewSource, accountService);
        SettingsPage = new SettingsPageViewModel(workerStatusService, accountService, ChatsPage.RefreshRoomsAsync);
        _currentPage = ChatsPage;
        ShowChatsCommand = new RelayCommand(() => Navigate("Chats", ChatsPage));
        ShowSettingsCommand = new AsyncRelayCommand(ShowSettingsAsync);
    }

    public async Task InitializeAsync()
    {
        await SettingsPage.InitializeAccountAsync();
        await ChatsPage.InitializeAsync();
        await SettingsPage.RefreshStatusAsync();
    }

    private async Task ShowSettingsAsync()
    {
        Navigate("Privacy & settings", SettingsPage);
        await SettingsPage.RefreshStatusAsync();
    }

    private void Navigate(string section, object page)
    {
        ActiveNavigation = section;
        CurrentPage = page;
    }
}
