using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VeilChat.Desktop.Core.Services;

public enum MatrixPeerIdentityStatus
{
    Unknown,
    Unverified,
    Verified,
    PreviouslyVerified,
    VerificationViolation,
}

public sealed record MatrixDirectRoom(
    string RoomId,
    bool Encrypted,
    bool EncryptionKnown,
    string PeerUserId,
    MatrixPeerIdentityStatus PeerIdentityStatus);

public sealed record MatrixRoomInvite(string RoomId, bool IsDirect, bool Encrypted, bool EncryptionKnown);

public sealed record MatrixTextMessage(string? EventId, string Sender, string Body);

public sealed record MatrixVerificationEmoji(string Symbol, string Description);

public sealed record MatrixPeerVerification(
    string PeerUserId,
    string FlowId,
    string State,
    IReadOnlyList<MatrixVerificationEmoji> Emojis,
    IReadOnlyList<int> Decimals,
    MatrixPeerIdentityStatus IdentityStatus)
{
    public string SasDisplay => Emojis.Count == 7
        ? string.Join("  ", Emojis.Select(emoji => $"{emoji.Symbol} {emoji.Description}"))
        : Decimals.Count == 3
            ? string.Join(" – ", Decimals.Select(number => number.ToString("D3", System.Globalization.CultureInfo.InvariantCulture)))
            : "";
}

public sealed class MatrixAccountService
{
    private static readonly TimeSpan MatrixOperationTimeout = TimeSpan.FromMinutes(4);
    private readonly WorkerProcessService _worker;
    private readonly ISecureMatrixSessionStore _sessionStore;

    public string? UserId { get; private set; }

    public string? Homeserver { get; private set; }

    public bool IsAuthenticated => !string.IsNullOrWhiteSpace(UserId);

    public bool HasSavedSession { get; private set; }

    public MatrixAccountService(WorkerProcessService worker, ISecureMatrixSessionStore sessionStore)
    {
        ArgumentNullException.ThrowIfNull(worker);
        ArgumentNullException.ThrowIfNull(sessionStore);
        _worker = worker;
        _sessionStore = sessionStore;
    }

    public async Task<bool> RestoreSessionAsync(CancellationToken cancellationToken = default)
    {
        var stored = await _sessionStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (stored is null)
        {
            HasSavedSession = false;
            return false;
        }

        HasSavedSession = true;
        try
        {
            var response = await _worker.SendCommandAsync(
                Ipc.WorkerMethod.MatrixRestore,
                new
                {
                    homeserver = stored.Homeserver,
                    session = stored.Session,
                    storePassphrase = stored.StorePassphrase,
                    storeId = stored.StoreId,
                },
                MatrixOperationTimeout,
                cancellationToken).ConfigureAwait(false);
            UserId = response.GetProperty("userId").GetString();
            Homeserver = stored.Homeserver;
            return true;
        }
        catch (WorkerServiceException exception) when (exception.ErrorCode == Ipc.WorkerErrorCode.AuthenticationFailed)
        {
            await _sessionStore.DeleteAsync(cancellationToken).ConfigureAwait(false);
            HasSavedSession = false;
            UserId = null;
            Homeserver = null;
            throw;
        }
    }

    public async Task<string> LoginAsync(
        string homeserver,
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        ValidateHomeserver(homeserver);
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrEmpty(password);
        if (Encoding.UTF8.GetByteCount(username) > 255 || Encoding.UTF8.GetByteCount(password) > 4096)
        {
            throw new ArgumentException("The login input exceeds its supported length.");
        }

        var randomPassphrase = RandomNumberGenerator.GetBytes(32);
        var storePassphrase = Convert.ToHexString(randomPassphrase);
        CryptographicOperations.ZeroMemory(randomPassphrase);
        var storeId = Guid.NewGuid().ToString("D");
        var response = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.MatrixLogin,
            new { homeserver, username, password, storePassphrase, storeId },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);

        var userId = response.GetProperty("userId").GetString()
            ?? throw new WorkerServiceException(WorkerServiceFailure.MalformedResponse);
        var session = response.GetProperty("session").Clone();
        try
        {
            await _sessionStore.SaveAsync(
                new SecureMatrixSession(homeserver, session, storePassphrase, storeId),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            try
            {
                await _worker.SendCommandAsync(
                    Ipc.WorkerMethod.MatrixLogout,
                    new { },
                    MatrixOperationTimeout,
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception cleanupException) when (cleanupException is not OutOfMemoryException)
            {
                // The process is stopped below even if the server logout cannot complete.
            }
            await _worker.StopWorkerAsync(CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException("The OS secure store could not retain the Matrix session. Login was not kept in this app.");
        }

        UserId = userId;
        Homeserver = homeserver;
        HasSavedSession = true;
        return userId;
    }

    public async Task<IReadOnlyList<MatrixDirectRoom>> GetEncryptedDirectRoomsAsync(CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        var response = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.RoomsList,
            new { },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
        return response.GetProperty("rooms").EnumerateArray()
            .Select(room => new MatrixDirectRoom(
                room.GetProperty("roomId").GetString()!,
                room.GetProperty("encrypted").GetBoolean(),
                room.GetProperty("encryptionKnown").GetBoolean(),
                room.GetProperty("peerUserId").GetString()!,
                ParsePeerIdentityStatus(room.GetProperty("peerIdentityStatus").GetString()!)))
            .ToArray();
    }

    public async Task<IReadOnlyList<MatrixRoomInvite>> GetInvitesAsync(CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        var response = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.InvitesList,
            new { },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
        return response.GetProperty("invites").EnumerateArray()
            .Select(invite => new MatrixRoomInvite(
                invite.GetProperty("roomId").GetString()!,
                invite.GetProperty("isDirect").GetBoolean(),
                invite.GetProperty("encrypted").GetBoolean(),
                invite.GetProperty("encryptionKnown").GetBoolean()))
            .ToArray();
    }

    public async Task AcceptEncryptedDirectInviteAsync(string roomId, CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        var response = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.RoomAcceptInvite,
            new { roomId },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
        if (response.GetProperty("encrypted").ValueKind != JsonValueKind.True ||
            response.GetProperty("encryptionKnown").ValueKind != JsonValueKind.True)
        {
            throw new WorkerServiceException(WorkerServiceFailure.RemoteError, Ipc.WorkerErrorCode.EncryptionRequired);
        }
    }

    public async Task<MatrixDirectRoom> CreateEncryptedDirectRoomAsync(string userId, CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        var response = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.RoomCreateDirect,
            new { userId },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
        var result = new MatrixDirectRoom(
            response.GetProperty("roomId").GetString()!,
            response.GetProperty("encrypted").GetBoolean(),
            response.GetProperty("encrypted").GetBoolean(),
            userId,
            MatrixPeerIdentityStatus.Unknown);
        if (!result.Encrypted)
        {
            throw new WorkerServiceException(WorkerServiceFailure.RemoteError, Ipc.WorkerErrorCode.EncryptionRequired);
        }
        return result;
    }

    public async Task<IReadOnlyList<MatrixTextMessage>> GetTextMessagesAsync(string roomId, CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        var response = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.RoomMessages,
            new { roomId },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!response.GetProperty("encrypted").GetBoolean())
        {
            throw new WorkerServiceException(WorkerServiceFailure.RemoteError, Ipc.WorkerErrorCode.EncryptionRequired);
        }
        return response.GetProperty("events").EnumerateArray()
            .Select(message => new MatrixTextMessage(
                message.GetProperty("eventId").ValueKind == JsonValueKind.String
                    ? message.GetProperty("eventId").GetString()
                    : null,
                message.GetProperty("sender").GetString()!,
                message.GetProperty("body").GetString()!))
            .ToArray();
    }

    public async Task SendEncryptedTextAsync(string roomId, string body, CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        _ = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.RoomSendText,
            new { roomId, body },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<MatrixPeerVerification> StartPeerVerificationAsync(
        string peerUserId,
        CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        var response = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.PeerVerificationStart,
            new { peerUserId },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
        return ParsePeerVerification(response);
    }

    public async Task<MatrixPeerVerification> GetPeerVerificationStatusAsync(
        string peerUserId,
        string flowId,
        CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        var response = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.PeerVerificationStatus,
            new { peerUserId, flowId },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
        return ParsePeerVerification(response);
    }

    public async Task ConfirmPeerVerificationAsync(
        string peerUserId,
        string flowId,
        CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        _ = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.PeerVerificationConfirm,
            new { peerUserId, flowId },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task CancelPeerVerificationAsync(
        string peerUserId,
        string flowId,
        CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        _ = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.PeerVerificationCancel,
            new { peerUserId, flowId },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();
        _ = await _worker.SendCommandAsync(
            Ipc.WorkerMethod.MatrixLogout,
            new { },
            MatrixOperationTimeout,
            cancellationToken).ConfigureAwait(false);
        await _sessionStore.DeleteAsync(cancellationToken).ConfigureAwait(false);
        HasSavedSession = false;
        UserId = null;
        Homeserver = null;
    }

    public async Task ForgetLocalSessionAsync(CancellationToken cancellationToken = default)
    {
        await _sessionStore.DeleteAsync(cancellationToken).ConfigureAwait(false);
        await _worker.StopWorkerAsync(cancellationToken).ConfigureAwait(false);
        HasSavedSession = false;
        UserId = null;
        Homeserver = null;
    }

    private void EnsureAuthenticated()
    {
        if (!IsAuthenticated)
        {
            throw new WorkerServiceException(WorkerServiceFailure.RemoteError, Ipc.WorkerErrorCode.NotLoggedIn);
        }
    }

    private static MatrixPeerIdentityStatus ParsePeerIdentityStatus(string value) => value switch
    {
        "unknown" => MatrixPeerIdentityStatus.Unknown,
        "unverified" => MatrixPeerIdentityStatus.Unverified,
        "verified" => MatrixPeerIdentityStatus.Verified,
        "previously_verified" => MatrixPeerIdentityStatus.PreviouslyVerified,
        "verification_violation" => MatrixPeerIdentityStatus.VerificationViolation,
        _ => throw new InvalidOperationException("The worker returned an unknown peer identity status."),
    };

    private static MatrixPeerVerification ParsePeerVerification(JsonElement response) => new(
        response.GetProperty("peerUserId").GetString()!,
        response.GetProperty("flowId").GetString()!,
        response.GetProperty("state").GetString()!,
        response.GetProperty("emojis").EnumerateArray()
            .Select(emoji => new MatrixVerificationEmoji(
                emoji.GetProperty("symbol").GetString()!,
                emoji.GetProperty("description").GetString()!))
            .ToArray(),
        response.GetProperty("decimals").EnumerateArray().Select(value => value.GetInt32()).ToArray(),
        ParsePeerIdentityStatus(response.GetProperty("identityStatus").GetString()!));

    private static void ValidateHomeserver(string homeserver)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(homeserver);
        if (!Uri.TryCreate(homeserver, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException("Homeserver must be an HTTPS URL without embedded credentials.", nameof(homeserver));
        }
    }
}
