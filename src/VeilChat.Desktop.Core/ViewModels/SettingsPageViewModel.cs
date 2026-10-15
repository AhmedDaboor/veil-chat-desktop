using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VeilChat.Desktop.Core.Services;
using VeilChat.Desktop.Core.Ipc;

namespace VeilChat.Desktop.Core.ViewModels;

public sealed class SettingsPageViewModel : ObservableObject
{
    private readonly IWorkerStatusService _workerStatusService;
    private string _workerConnectionState = "Not started";
    private string _workerPrivacyState = "Not queried";
    private string _workerNetworkAccess = "Not queried";
    private string _workerDetails = "The worker starts only when this status is refreshed.";
    private bool _isRefreshing;
    private readonly MatrixAccountService? _accountService;
    private readonly Func<Task>? _accountChanged;
    private string _homeserver = "https://matrix.org";
    private string _username = "";
    private string _password = "";
    private string _accountState = "No account session is active.";
    private string _accountError = "";
    private bool _isAccountBusy;
    private bool _hasSavedSession;

    public string WorkerConnectionState
    {
        get => _workerConnectionState;
        private set => SetProperty(ref _workerConnectionState, value);
    }

    public string WorkerPrivacyState
    {
        get => _workerPrivacyState;
        private set => SetProperty(ref _workerPrivacyState, value);
    }

    public string WorkerNetworkAccess
    {
        get => _workerNetworkAccess;
        private set => SetProperty(ref _workerNetworkAccess, value);
    }

    public string WorkerDetails
    {
        get => _workerDetails;
        private set => SetProperty(ref _workerDetails, value);
    }

    public bool IsRefreshing
    {
        get => _isRefreshing;
        private set => SetProperty(ref _isRefreshing, value);
    }

    private string _encryptionState = "SDK encryption support is available; no authenticated encrypted room is active.";

    private string _torState = "Tor is not configured; network operations are blocked.";

    private string _matrixState = "Matrix SDK account, sync, and encrypted direct text flows are available; requests remain gated by Tor.";

    public string EncryptionState
    {
        get => _encryptionState;
        private set => SetProperty(ref _encryptionState, value);
    }

    public string TorState
    {
        get => _torState;
        private set => SetProperty(ref _torState, value);
    }

    public string MatrixState
    {
        get => _matrixState;
        private set => SetProperty(ref _matrixState, value);
    }

    public string AdvisoryState => "Informational only: RUSTSEC-2026-0319 marks anymap2 0.13.0 as unmaintained; it reports no vulnerability. The current official SDK dependency path has no patched version, so review is required before production.";

    public IAsyncRelayCommand RefreshStatusCommand { get; }

    public IAsyncRelayCommand LoginCommand { get; }

    public IAsyncRelayCommand RestoreSessionCommand { get; }

    public IAsyncRelayCommand LogoutCommand { get; }

    public IAsyncRelayCommand ForgetLocalSessionCommand { get; }

    public string Homeserver { get => _homeserver; set => SetProperty(ref _homeserver, value); }
    public string Username { get => _username; set => SetProperty(ref _username, value); }
    public string Password { get => _password; set => SetProperty(ref _password, value); }
    public string AccountState { get => _accountState; private set => SetProperty(ref _accountState, value); }
    public string AccountError { get => _accountError; private set => SetProperty(ref _accountError, value); }
    public bool IsAccountBusy { get => _isAccountBusy; private set => SetProperty(ref _isAccountBusy, value); }
    public bool HasSavedSession { get => _hasSavedSession; private set => SetProperty(ref _hasSavedSession, value); }
    public bool IsAuthenticated => _accountService?.IsAuthenticated == true;

    public SettingsPageViewModel(
        IWorkerStatusService workerStatusService,
        MatrixAccountService? accountService = null,
        Func<Task>? accountChanged = null)
    {
        ArgumentNullException.ThrowIfNull(workerStatusService);
        _workerStatusService = workerStatusService;
        _accountService = accountService;
        _accountChanged = accountChanged;
        RefreshStatusCommand = new AsyncRelayCommand(RefreshStatusAsync);
        LoginCommand = new AsyncRelayCommand(LoginAsync);
        RestoreSessionCommand = new AsyncRelayCommand(RestoreSessionAsync);
        LogoutCommand = new AsyncRelayCommand(LogoutAsync);
        ForgetLocalSessionCommand = new AsyncRelayCommand(ForgetLocalSessionAsync);
    }

    public async Task InitializeAccountAsync()
    {
        if (_accountService is null) return;
        try
        {
            HasSavedSession = await _accountService.RestoreSessionAsync();
            if (HasSavedSession)
            {
                AccountState = $"Signed in as {_accountService.UserId}.";
            }
            else AccountState = "No saved Matrix session.";
        }
        catch (WorkerServiceException exception)
        {
            HasSavedSession = _accountService.HasSavedSession;
            AccountState = HasSavedSession ? "A protected session is saved but could not be resumed." : "No active Matrix session.";
            AccountError = SafeAccountError(exception);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            AccountError = "The operating system secure session store is unavailable. Login is not available.";
        }
        finally
        {
            OnPropertyChanged(nameof(IsAuthenticated));
        }
    }

    private async Task LoginAsync()
    {
        if (_accountService is null) return;
        if (_accountService.IsAuthenticated || HasSavedSession)
        {
            AccountError = "Restore the saved session or sign out/forget it before signing in to another account.";
            return;
        }
        IsAccountBusy = true;
        AccountError = "";
        try
        {
            var userId = await _accountService.LoginAsync(Homeserver.Trim(), Username.Trim(), Password);
            HasSavedSession = true;
            AccountState = $"Signed in as {userId}.";
            Password = "";
            if (_accountChanged is not null) await _accountChanged();
        }
        catch (WorkerServiceException exception) { AccountError = SafeAccountError(exception); }
        catch (ArgumentException) { AccountError = "Check the HTTPS homeserver, username, and password fields."; }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            AccountError = "Login could not be completed or safely stored. Check the worker, Tor, and OS secure-store configuration.";
        }
        finally
        {
            Password = "";
            IsAccountBusy = false;
            OnPropertyChanged(nameof(IsAuthenticated));
        }
    }

    private async Task RestoreSessionAsync()
    {
        if (_accountService is null) return;
        IsAccountBusy = true;
        AccountError = "";
        try
        {
            HasSavedSession = await _accountService.RestoreSessionAsync();
            AccountState = HasSavedSession ? $"Signed in as {_accountService.UserId}." : "No saved Matrix session.";
            if (HasSavedSession && _accountChanged is not null) await _accountChanged();
        }
        catch (WorkerServiceException exception)
        {
            HasSavedSession = _accountService.HasSavedSession;
            AccountState = HasSavedSession ? "A protected session is saved but could not be resumed." : "No active Matrix session.";
            AccountError = SafeAccountError(exception);
        }
        catch (Exception exception) when (exception is InvalidOperationException or CryptographicException or PlatformNotSupportedException)
        {
            AccountError = "The protected session could not be read from the OS secure store.";
        }
        finally
        {
            IsAccountBusy = false;
            OnPropertyChanged(nameof(IsAuthenticated));
        }
    }

    private async Task LogoutAsync()
    {
        if (_accountService is null) return;
        IsAccountBusy = true;
        AccountError = "";
        try
        {
            await _accountService.LogoutAsync();
            HasSavedSession = false;
            AccountState = "Signed out.";
            if (_accountChanged is not null) await _accountChanged();
        }
        catch (WorkerServiceException exception) { AccountError = SafeAccountError(exception); }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            AccountError = "Logout could not be completed. If Tor is unavailable, use Forget local session to remove protected credentials.";
        }
        finally
        {
            IsAccountBusy = false;
            OnPropertyChanged(nameof(IsAuthenticated));
        }
    }

    private async Task ForgetLocalSessionAsync()
    {
        if (_accountService is null) return;
        IsAccountBusy = true;
        AccountError = "";
        try
        {
            await _accountService.ForgetLocalSessionAsync();
            HasSavedSession = false;
            AccountState = "Protected local credentials removed. This may not revoke the server session.";
            if (_accountChanged is not null) await _accountChanged();
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            AccountError = "The protected local session could not be removed.";
        }
        finally
        {
            IsAccountBusy = false;
            OnPropertyChanged(nameof(IsAuthenticated));
        }
    }

    private static string SafeAccountError(WorkerServiceException exception) => exception.ErrorCode switch
    {
        WorkerErrorCode.TorNotConfigured => "Tor is not configured. Login and session restore are blocked without a Tor route.",
        WorkerErrorCode.TorNotReady => "Tor is not ready. No Matrix request was sent directly.",
        WorkerErrorCode.AuthenticationFailed => "Matrix authentication failed. Check the server and credentials.",
        WorkerErrorCode.NotLoggedIn => "No active Matrix session is available.",
        _ => "The worker could not complete the account operation. Credentials are not shown.",
    };

    public async Task RefreshStatusAsync(CancellationToken cancellationToken = default)
    {
        IsRefreshing = true;
        WorkerDetails = "Checking the local worker.";
        try
        {
            var status = await _workerStatusService.GetPrivacyStatusAsync(cancellationToken);
            var tor = await _workerStatusService.GetTorStatusAsync(cancellationToken);
            WorkerConnectionState = "Connected — worker.hello succeeded.";
            WorkerPrivacyState = status.State;
            WorkerNetworkAccess = status.NetworkAccess;
            WorkerDetails = "Worker IPC is connected. Network operations remain blocked until the worker verifies its supervised Tor process.";
            EncryptionState = status.E2eeState == "sdk_feature_available"
                ? "The official SDK includes E2EE. Room encryption is checked before history or send; peer/device identity verification is not implemented."
                : "E2EE is unavailable until the SDK reports support.";
            TorState = tor.State switch
            {
                "bootstrap_verified" when tor.NetworkOperationsAllowed => "The owned Tor process reports bootstrap 100 and the expected loopback SOCKS listener through SAFECOOKIE-authenticated control. Matrix requests are gated on this check.",
                "configured_not_started" => "Tor executable is configured but not started. Network operations are blocked until bootstrap completes.",
                "not_ready" => "Tor is not ready. Network operations are blocked.",
                _ => "Tor is not configured. Network operations are blocked; there is no direct-network fallback.",
            };
        }
        catch (WorkerServiceException exception)
        {
            WorkerPrivacyState = "Unavailable";
            WorkerNetworkAccess = "Unavailable";
            (WorkerConnectionState, WorkerDetails) = exception.Failure switch
            {
                WorkerServiceFailure.NotConfigured => (
                    "Not configured",
                    "Set VEIL_CHAT_WORKER_EXECUTABLE, or explicitly configure the WSL executable and distribution."),
                WorkerServiceFailure.StartupFailed => (
                    "Unavailable",
                    "The configured worker could not be started. Check the executable configuration."),
                WorkerServiceFailure.WorkerExited => (
                    "Disconnected",
                    "The worker exited or closed its IPC pipe. Refresh to start a new worker."),
                WorkerServiceFailure.MalformedResponse => (
                    "Rejected",
                    "The worker response did not match the typed IPC protocol. The process was stopped."),
                WorkerServiceFailure.RequestTimeout => (
                    "Timed out",
                    "The worker did not answer in time. The process was stopped."),
                WorkerServiceFailure.RemoteError => (
                    "Connected — worker returned an IPC error",
                    $"Worker error: {exception.ErrorCode}."),
                _ => ("Unavailable", "The worker request could not be completed."),
            };
        }
        catch (OperationCanceledException)
        {
            WorkerConnectionState = "Disconnected";
            WorkerPrivacyState = "Unavailable";
            WorkerNetworkAccess = "Unavailable";
            WorkerDetails = "The request was cancelled and the worker process was stopped.";
        }
        catch (ObjectDisposedException)
        {
            WorkerConnectionState = "Stopped";
            WorkerPrivacyState = "Unavailable";
            WorkerNetworkAccess = "Unavailable";
            WorkerDetails = "The worker service has been disposed.";
        }
        finally
        {
            IsRefreshing = false;
        }
    }
}
