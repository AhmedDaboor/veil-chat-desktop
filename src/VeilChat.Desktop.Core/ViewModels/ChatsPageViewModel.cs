using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VeilChat.Desktop.Core.Ipc;
using VeilChat.Desktop.Core.Models;
using VeilChat.Desktop.Core.Services;

namespace VeilChat.Desktop.Core.ViewModels;

public sealed record ChatConversationItem(
    string DisplayName,
    string Preview,
    string TimeLabel,
    string? RoomId,
    bool IsEncrypted,
    bool IsMock,
    MatrixPeerIdentityStatus? PeerIdentityStatus = null,
    string? PeerUserId = null)
{
    public string PeerIdentityStatusText => IsMock
        ? "Sample conversation · no Matrix identity"
        : PeerIdentityStatus switch
        {
            MatrixPeerIdentityStatus.Verified => "Matrix SDK reports the peer identity verified",
            MatrixPeerIdentityStatus.VerificationViolation => "Security warning: peer identity changed after verification",
            MatrixPeerIdentityStatus.PreviouslyVerified => "Previously verified · verify again before relying on identity",
            MatrixPeerIdentityStatus.Unverified => "Peer identity not verified",
            _ => "Peer identity status unknown",
        };
}

public sealed record ChatMessageItem(string Speaker, string Text, string TimeLabel, bool IsEncrypted, bool IsMock);

public sealed record ChatInviteItem(string RoomId, bool IsDirect, bool IsEncrypted, bool EncryptionKnown)
{
    public bool CanAccept => IsDirect && IsEncrypted && EncryptionKnown;

    public string SecurityStatus => !IsDirect
        ? "Not a direct invite"
        : !EncryptionKnown
            ? "Encryption state unknown"
            : !IsEncrypted
                ? "Not end-to-end encrypted"
                : "Encrypted direct invite";
}

public sealed class ChatsPageViewModel : ObservableObject
{
    private readonly IConversationPreviewSource _previewSource;
    private readonly MatrixAccountService? _accountService;
    private ChatConversationItem? _activeConversation;
    private ChatInviteItem? _activeInvite;
    private string _directUserId = "";
    private string _draftText = "";
    private string _statusMessage = "Sample content is local mock data. Sign in to load encrypted Matrix rooms.";
    private bool _isBusy;
    private bool _isAuthenticated;
    private int _messageLoadGeneration;
    private MatrixPeerVerification? _peerVerification;

    public ObservableCollection<ChatConversationItem> Conversations { get; } = [];

    public ObservableCollection<ChatMessageItem> Messages { get; } = [];

    public ObservableCollection<ChatInviteItem> Invites { get; } = [];

    public ChatConversationItem? ActiveConversation
    {
        get => _activeConversation;
        set
        {
            if (SetProperty(ref _activeConversation, value))
            {
                var generation = Interlocked.Increment(ref _messageLoadGeneration);
                OnPropertyChanged(nameof(CanSend));
                NotifyPeerVerificationProperties();
                if (value is { IsMock: false, RoomId: not null })
                {
                    _ = LoadMessagesAsync(value, generation);
                }
                else if (value?.IsMock == true)
                {
                    LoadMockMessages();
                }
                else
                {
                    Messages.Clear();
                }
            }
        }
    }

    public ChatInviteItem? ActiveInvite
    {
        get => _activeInvite;
        set
        {
            if (SetProperty(ref _activeInvite, value)) OnPropertyChanged(nameof(CanAcceptInvite));
        }
    }

    public string DirectUserId
    {
        get => _directUserId;
        set => SetProperty(ref _directUserId, value);
    }

    public string DraftText
    {
        get => _draftText;
        set
        {
            if (SetProperty(ref _draftText, value)) OnPropertyChanged(nameof(CanSend));
        }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                OnPropertyChanged(nameof(CanSend));
                OnPropertyChanged(nameof(CanAcceptInvite));
                NotifyPeerVerificationProperties();
            }
        }
    }

    public bool IsAuthenticated
    {
        get => _isAuthenticated;
        private set
        {
            if (SetProperty(ref _isAuthenticated, value))
            {
                OnPropertyChanged(nameof(IsMockMode));
                OnPropertyChanged(nameof(CanSend));
                OnPropertyChanged(nameof(CanAcceptInvite));
                NotifyPeerVerificationProperties();
            }
        }
    }

    public bool IsMockMode => !IsAuthenticated;

    public bool CanSend => IsAuthenticated && !IsBusy && ActiveConversation is { IsMock: false, IsEncrypted: true } &&
        !string.IsNullOrWhiteSpace(DraftText);

    public bool CanAcceptInvite => IsAuthenticated && !IsBusy && ActiveInvite?.CanAccept == true;

    public MatrixPeerVerification? PeerVerification
    {
        get => _peerVerification;
        private set
        {
            if (SetProperty(ref _peerVerification, value)) NotifyPeerVerificationProperties();
        }
    }

    public bool CanStartPeerVerification => IsAuthenticated && !IsBusy && _accountService is not null &&
        ActiveConversation is { IsMock: false, IsEncrypted: true, PeerUserId: not null } conversation &&
        conversation.PeerIdentityStatus != MatrixPeerIdentityStatus.Verified &&
        (PeerVerification is null || IsPeerVerificationTerminal(PeerVerification.State));

    public bool CanRefreshPeerVerification => IsAuthenticated && !IsBusy &&
        PeerVerification is { } verification && !IsPeerVerificationTerminal(verification.State) &&
        ActiveConversation?.PeerUserId == verification.PeerUserId;

    public bool CanConfirmPeerVerification => IsAuthenticated && !IsBusy &&
        PeerVerification is { State: "sas_ready" } verification &&
        ActiveConversation?.PeerUserId == verification.PeerUserId;

    public bool CanCancelPeerVerification => IsAuthenticated && !IsBusy &&
        PeerVerification is { } verification && !IsPeerVerificationTerminal(verification.State) &&
        ActiveConversation?.PeerUserId == verification.PeerUserId;

    public bool IsPeerVerificationSasVisible => PeerVerification is { State: "sas_ready" or "confirming" } verification &&
        ActiveConversation?.PeerUserId == verification.PeerUserId;

    public string PeerVerificationMessage => PeerVerification is not { } verification
        ? "Use the Matrix SDK SAS flow to verify this peer. Compare the string through a trusted separate channel before confirming."
        : ActiveConversation?.PeerUserId != verification.PeerUserId
            ? $"Verification is active with {verification.PeerUserId}. Return to that room to manage it."
            : verification.State switch
            {
                "waiting" => "Verification request sent. Waiting for the peer to accept using a compatible Matrix client.",
                "sas_ready" => "Compare all seven emoji or all three number groups with the peer over a trusted separate channel. Confirm only when they match.",
                "confirming" => "Your comparison was confirmed. Waiting for the peer to confirm the same SAS.",
                "completed" when verification.IdentityStatus == MatrixPeerIdentityStatus.Verified =>
                    "The Matrix SDK now reports this peer identity verified after both sides confirmed the SAS.",
                "completed" => "The verification flow completed, but the SDK does not report the peer identity as verified. Refresh room status before relying on it.",
                "cancelled" => "The verification was cancelled. No identity trust was added by this flow.",
                _ => "The SDK returned an unrecognized verification state. No trust is inferred.",
            };

    public string PeerVerificationSas => IsPeerVerificationSasVisible ? PeerVerification?.SasDisplay ?? "" : "";

    public IAsyncRelayCommand RefreshRoomsCommand { get; }
    public IAsyncRelayCommand CreateDirectRoomCommand { get; }
    public IAsyncRelayCommand AcceptInviteCommand { get; }
    public IAsyncRelayCommand SendMessageCommand { get; }
    public IAsyncRelayCommand StartPeerVerificationCommand { get; }
    public IAsyncRelayCommand RefreshPeerVerificationCommand { get; }
    public IAsyncRelayCommand ConfirmPeerVerificationCommand { get; }
    public IAsyncRelayCommand CancelPeerVerificationCommand { get; }

    public ChatsPageViewModel(IConversationPreviewSource previewSource, MatrixAccountService? accountService = null)
    {
        ArgumentNullException.ThrowIfNull(previewSource);
        _previewSource = previewSource;
        _accountService = accountService;
        RefreshRoomsCommand = new AsyncRelayCommand(RefreshRoomsAsync);
        CreateDirectRoomCommand = new AsyncRelayCommand(CreateDirectRoomAsync);
        AcceptInviteCommand = new AsyncRelayCommand(AcceptInviteAsync);
        SendMessageCommand = new AsyncRelayCommand(SendMessageAsync);
        StartPeerVerificationCommand = new AsyncRelayCommand(StartPeerVerificationAsync);
        RefreshPeerVerificationCommand = new AsyncRelayCommand(RefreshPeerVerificationAsync);
        ConfirmPeerVerificationCommand = new AsyncRelayCommand(ConfirmPeerVerificationAsync);
        CancelPeerVerificationCommand = new AsyncRelayCommand(CancelPeerVerificationAsync);
        LoadMockConversations();
        LoadMockMessages();
    }

    public async Task InitializeAsync()
    {
        IsAuthenticated = _accountService?.IsAuthenticated == true;
        if (IsAuthenticated) await RefreshRoomsAsync();
    }

    public async Task RefreshRoomsAsync()
    {
        if (_accountService is null || !_accountService.IsAuthenticated)
        {
            IsAuthenticated = false;
            StatusMessage = "Sample content is local mock data. Sign in to load encrypted Matrix rooms.";
            Invites.Clear();
            ActiveInvite = null;
            LoadMockConversations();
            LoadMockMessages();
            return;
        }

        IsBusy = true;
        try
        {
            await RefreshAuthenticatedRoomsAsync();
        }
        catch (WorkerServiceException exception)
        {
            StatusMessage = SafeError(exception);
            Conversations.Clear();
            ActiveConversation = null;
            Invites.Clear();
            ActiveInvite = null;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task CreateDirectRoomAsync()
    {
        if (_accountService is null || !_accountService.IsAuthenticated || string.IsNullOrWhiteSpace(DirectUserId)) return;
        IsBusy = true;
        try
        {
            var room = await _accountService.CreateEncryptedDirectRoomAsync(DirectUserId.Trim());
            if (!room.Encrypted || !room.EncryptionKnown)
            {
                StatusMessage = "The room's encryption state could not be verified. It will not be used for messaging.";
                return;
            }
            DirectUserId = "";
            await RefreshAuthenticatedRoomsAsync();
            ActiveConversation = Conversations.FirstOrDefault(item => item.RoomId == room.RoomId);
        }
        catch (WorkerServiceException exception)
        {
            StatusMessage = SafeError(exception);
        }
        catch (ArgumentException)
        {
            StatusMessage = "Enter a valid Matrix user ID.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task AcceptInviteAsync()
    {
        var invite = ActiveInvite;
        if (!CanAcceptInvite || _accountService is null || invite is null) return;
        IsBusy = true;
        try
        {
            await _accountService.AcceptEncryptedDirectInviteAsync(invite.RoomId);
            await RefreshAuthenticatedRoomsAsync();
            ActiveConversation = Conversations.FirstOrDefault(item => item.RoomId == invite.RoomId);
            StatusMessage = "Joined the direct room after the Matrix SDK confirmed its encryption state.";
        }
        catch (WorkerServiceException exception)
        {
            StatusMessage = SafeError(exception);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RefreshAuthenticatedRoomsAsync()
    {
        if (_accountService is null || !_accountService.IsAuthenticated) return;
        var rooms = await _accountService.GetEncryptedDirectRoomsAsync();
        var invites = await _accountService.GetInvitesAsync();
        IsAuthenticated = true;
        Conversations.Clear();
        foreach (var room in rooms.Where(room => room.Encrypted && room.EncryptionKnown))
        {
            Conversations.Add(new ChatConversationItem(
                room.RoomId,
                "Matrix SDK reports room encrypted",
                "",
                room.RoomId,
                true,
                false,
                room.PeerIdentityStatus,
                room.PeerUserId));
        }
        Invites.Clear();
        foreach (var invite in invites)
        {
            Invites.Add(new ChatInviteItem(invite.RoomId, invite.IsDirect, invite.Encrypted, invite.EncryptionKnown));
        }
        ActiveInvite = Invites.FirstOrDefault();
        ActiveConversation = Conversations.FirstOrDefault();
        StatusMessage = Conversations.Count == 0
            ? "No encrypted direct rooms are available. Accept a verified encrypted invite or create one by Matrix user ID."
            : $"Loaded {Conversations.Count} encrypted direct room(s) and {Invites.Count} invitation(s).";
    }

    private async Task SendMessageAsync()
    {
        var conversation = ActiveConversation;
        if (!CanSend || _accountService is null || conversation?.RoomId is not { } roomId) return;
        var body = DraftText;
        IsBusy = true;
        try
        {
            await _accountService.SendEncryptedTextAsync(roomId, body);
            DraftText = "";
            await LoadMessagesAsync(conversation, Volatile.Read(ref _messageLoadGeneration));
            StatusMessage = "Message sent through the configured Tor route in a room reported encrypted by the Matrix SDK.";
        }
        catch (WorkerServiceException exception)
        {
            StatusMessage = SafeError(exception);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task StartPeerVerificationAsync()
    {
        var conversation = ActiveConversation;
        if (!CanStartPeerVerification || _accountService is null || conversation?.PeerUserId is not { } peerUserId) return;
        IsBusy = true;
        try
        {
            PeerVerification = await _accountService.StartPeerVerificationAsync(peerUserId);
            StatusMessage = "SAS verification request sent through the configured Tor route. Encryption by itself does not verify this peer.";
        }
        catch (WorkerServiceException exception)
        {
            StatusMessage = SafeError(exception);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RefreshPeerVerificationAsync()
    {
        var verification = PeerVerification;
        if (!CanRefreshPeerVerification || _accountService is null || verification is null) return;
        IsBusy = true;
        try
        {
            PeerVerification = await _accountService.GetPeerVerificationStatusAsync(
                verification.PeerUserId,
                verification.FlowId);
            if (PeerVerification.State == "completed")
            {
                await RefreshAuthenticatedRoomsAsync();
                StatusMessage = PeerVerificationMessage;
            }
        }
        catch (WorkerServiceException exception)
        {
            StatusMessage = SafeError(exception);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ConfirmPeerVerificationAsync()
    {
        var verification = PeerVerification;
        if (!CanConfirmPeerVerification || _accountService is null || verification is null) return;
        IsBusy = true;
        try
        {
            await _accountService.ConfirmPeerVerificationAsync(verification.PeerUserId, verification.FlowId);
            PeerVerification = verification with { State = "confirming" };
            StatusMessage = "SAS confirmation sent. The SDK will report verified only after the peer also confirms.";
        }
        catch (WorkerServiceException exception)
        {
            StatusMessage = SafeError(exception);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task CancelPeerVerificationAsync()
    {
        var verification = PeerVerification;
        if (!CanCancelPeerVerification || _accountService is null || verification is null) return;
        IsBusy = true;
        try
        {
            await _accountService.CancelPeerVerificationAsync(verification.PeerUserId, verification.FlowId);
            PeerVerification = verification with { State = "cancelled" };
            StatusMessage = "Verification cancelled. No identity trust was added by this flow.";
        }
        catch (WorkerServiceException exception)
        {
            StatusMessage = SafeError(exception);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void NotifyPeerVerificationProperties()
    {
        OnPropertyChanged(nameof(CanStartPeerVerification));
        OnPropertyChanged(nameof(CanRefreshPeerVerification));
        OnPropertyChanged(nameof(CanConfirmPeerVerification));
        OnPropertyChanged(nameof(CanCancelPeerVerification));
        OnPropertyChanged(nameof(IsPeerVerificationSasVisible));
        OnPropertyChanged(nameof(PeerVerificationMessage));
        OnPropertyChanged(nameof(PeerVerificationSas));
    }

    private static bool IsPeerVerificationTerminal(string state) => state is "completed" or "cancelled";

    private async Task LoadMessagesAsync(ChatConversationItem conversation, int generation)
    {
        if (_accountService is null || conversation.RoomId is null) return;
        try
        {
            var messages = await _accountService.GetTextMessagesAsync(conversation.RoomId);
            if (generation != Volatile.Read(ref _messageLoadGeneration)) return;
            Messages.Clear();
            foreach (var message in messages)
            {
                Messages.Add(new ChatMessageItem(message.Sender, message.Body, "", true, false));
            }
            StatusMessage = "Showing text messages from a room reported encrypted by the Matrix SDK.";
        }
        catch (WorkerServiceException exception)
        {
            if (generation != Volatile.Read(ref _messageLoadGeneration)) return;
            Messages.Clear();
            StatusMessage = SafeError(exception);
        }
    }

    private void LoadMockConversations()
    {
        Conversations.Clear();
        foreach (var conversation in _previewSource.GetConversations())
        {
            Conversations.Add(new ChatConversationItem(conversation.DisplayName, conversation.Preview,
                conversation.TimeLabel, null, false, true));
        }
        ActiveConversation = Conversations.FirstOrDefault();
    }

    private void LoadMockMessages()
    {
        Messages.Clear();
        foreach (var message in _previewSource.GetMessages())
        {
            Messages.Add(new ChatMessageItem(message.Speaker, message.Text, message.TimeLabel, false, true));
        }
    }

    private static string SafeError(WorkerServiceException exception) => exception.ErrorCode switch
    {
        WorkerErrorCode.TorNotConfigured => "Tor is not configured. Network actions are blocked; there is no direct-network fallback.",
        WorkerErrorCode.TorNotReady => "Tor has not verified its bootstrap state. Network actions are blocked.",
        WorkerErrorCode.EncryptionRequired => "The room is not verified as end-to-end encrypted. The message was not used.",
        WorkerErrorCode.NotLoggedIn => "No active Matrix session is available.",
        WorkerErrorCode.VerificationUnavailable => "Peer verification is unavailable. Use an encrypted direct room with a supported Matrix identity and only one active verification at a time.",
        _ => "The worker could not complete the operation. No message content or credentials are shown here.",
    };
}
