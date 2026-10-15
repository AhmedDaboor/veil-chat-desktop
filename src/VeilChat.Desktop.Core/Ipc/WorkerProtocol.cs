using System.Text.Json;
using System.Security.Cryptography;
using System.Text;

namespace VeilChat.Desktop.Core.Ipc;

public enum WorkerMethod
{
    Hello,
    PrivacyStatus,
    TorStatus,
    MatrixLogin,
    MatrixRestore,
    MatrixLogout,
    RoomsList,
    InvitesList,
    RoomCreateDirect,
    RoomAcceptInvite,
    RoomMessages,
    RoomSendText,
    PeerVerificationStart,
    PeerVerificationStatus,
    PeerVerificationConfirm,
    PeerVerificationCancel,
}

public enum WorkerResponseKind
{
    Hello,
    PrivacyStatus,
    Generic,
}

public enum WorkerErrorCode
{
    InvalidRequest,
    MalformedRequest,
    FrameTooLarge,
    TruncatedFrame,
    UnsupportedVersion,
    UnknownMethod,
    OutputTooLarge,
    Cancelled,
    WorkerUnavailable,
    InternalError,
    TorNotConfigured,
    TorNotReady,
    AuthenticationFailed,
    DirectMessageRequired,
    EncryptionRequired,
    VerificationUnavailable,
    NotLoggedIn,
    OperationFailed,
    InvalidPayload,
}

public sealed record WorkerRequest(Guid Id, WorkerMethod Method, JsonElement Payload = default);

public sealed record RequestParseResult(
    WorkerRequest? Request,
    Guid? RequestId,
    WorkerErrorCode? ErrorCode)
{
    public bool IsSuccess => Request is not null && ErrorCode is null;

    internal static RequestParseResult Success(WorkerRequest request) =>
        new(request, request.Id, null);

    internal static RequestParseResult Failure(WorkerErrorCode errorCode, Guid? requestId = null) =>
        new(null, requestId, errorCode);
}

public sealed record WorkerResponse(
    Guid? RequestId,
    WorkerResponseKind? Result,
    WorkerErrorCode? ErrorCode,
    int? ProtocolVersion = null,
    string? PrivacyState = null,
    string? NetworkAccess = null,
    JsonElement? ResultPayload = null)
{
    public bool IsSuccess => Result is not null && ErrorCode is null;

    public static WorkerResponse Success(Guid requestId, WorkerResponseKind result) =>
        result switch
        {
            WorkerResponseKind.Hello => new(requestId, result, null, WorkerProtocol.CurrentVersion),
            WorkerResponseKind.PrivacyStatus => new(requestId, result, null, null, "matrix_sdk_available", "tor_required"),
            WorkerResponseKind.Generic => new(requestId, result, null),
            _ => new(requestId, result, null),
        };

    public static WorkerResponse Failure(Guid? requestId, WorkerErrorCode errorCode) =>
        new(requestId, null, errorCode);
}

public sealed record WorkerResponseParseResult(
    WorkerResponse? Response,
    WorkerErrorCode? ErrorCode)
{
    public bool IsSuccess => Response is not null && ErrorCode is null;

    internal static WorkerResponseParseResult Success(WorkerResponse response) => new(response, null);

    internal static WorkerResponseParseResult Failure(WorkerErrorCode errorCode) => new(null, errorCode);
}

public sealed class WorkerFrameException(WorkerErrorCode errorCode)
    : IOException("The worker IPC frame was rejected.")
{
    public WorkerErrorCode ErrorCode { get; } = errorCode;
}

/// <summary>
/// Version 2 of the typed UI/worker contract. Secret-bearing operations use the
/// same bounded JSONL framing and never expose diagnostics through response data.
/// </summary>
public static class WorkerProtocol
{
    public const int CurrentVersion = 2;
    public const int MaxFrameBytes = 64 * 1024;

    private const int MaxJsonDepth = 8;
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        MaxDepth = MaxJsonDepth,
    };

    public static RequestParseResult ParseRequest(ReadOnlySpan<byte> frame)
    {
        if (frame.Length > MaxFrameBytes)
        {
            return RequestParseResult.Failure(WorkerErrorCode.FrameTooLarge);
        }

        if (frame.IsEmpty)
        {
            return RequestParseResult.Failure(WorkerErrorCode.MalformedRequest);
        }

        byte[]? frameCopy = null;
        try
        {
            frameCopy = frame.ToArray();
            using var document = JsonDocument.Parse(frameCopy, new JsonDocumentOptions
            {
                MaxDepth = MaxJsonDepth,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });

            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return RequestParseResult.Failure(WorkerErrorCode.InvalidRequest);
            }

            var allowedProperties = new HashSet<string>(StringComparer.Ordinal)
            {
                "v", "kind", "id", "method", "payload",
            };
            var seenProperties = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!allowedProperties.Contains(property.Name) || !seenProperties.Add(property.Name))
                {
                    return RequestParseResult.Failure(WorkerErrorCode.InvalidRequest);
                }
            }

            if (seenProperties.Count != allowedProperties.Count ||
                !root.TryGetProperty("id", out var idElement) ||
                idElement.ValueKind != JsonValueKind.String ||
                !Guid.TryParseExact(idElement.GetString(), "D", out var requestId) ||
                requestId == Guid.Empty)
            {
                return RequestParseResult.Failure(WorkerErrorCode.InvalidRequest);
            }

            if (!root.TryGetProperty("v", out var versionElement) ||
                versionElement.ValueKind != JsonValueKind.Number ||
                !versionElement.TryGetInt32(out var version))
            {
                return RequestParseResult.Failure(WorkerErrorCode.InvalidRequest, requestId);
            }

            if (version != CurrentVersion)
            {
                return RequestParseResult.Failure(WorkerErrorCode.UnsupportedVersion, requestId);
            }

            if (!root.TryGetProperty("kind", out var kindElement) ||
                kindElement.ValueKind != JsonValueKind.String ||
                kindElement.GetString() != "request")
            {
                return RequestParseResult.Failure(WorkerErrorCode.InvalidRequest, requestId);
            }

            if (!root.TryGetProperty("method", out var methodElement) ||
                methodElement.ValueKind != JsonValueKind.String)
            {
                return RequestParseResult.Failure(WorkerErrorCode.InvalidRequest, requestId);
            }

            var methodText = methodElement.GetString();
            if (string.IsNullOrWhiteSpace(methodText) || methodText.Length > 64)
            {
                return RequestParseResult.Failure(WorkerErrorCode.InvalidRequest, requestId);
            }

            if (!root.TryGetProperty("payload", out var payloadElement) ||
                payloadElement.ValueKind != JsonValueKind.Object)
            {
                return RequestParseResult.Failure(WorkerErrorCode.InvalidRequest, requestId);
            }

            if (HasDuplicateProperties(payloadElement))
            {
                return RequestParseResult.Failure(WorkerErrorCode.InvalidRequest, requestId);
            }

            var method = methodText switch
            {
                "worker.hello" => WorkerMethod.Hello,
                "privacy.status" => WorkerMethod.PrivacyStatus,
                "tor.status" => WorkerMethod.TorStatus,
                "matrix.login" => WorkerMethod.MatrixLogin,
                "matrix.restore" => WorkerMethod.MatrixRestore,
                "matrix.logout" => WorkerMethod.MatrixLogout,
                "rooms.list" => WorkerMethod.RoomsList,
                "invites.list" => WorkerMethod.InvitesList,
                "room.create_dm" => WorkerMethod.RoomCreateDirect,
                "room.accept_invite" => WorkerMethod.RoomAcceptInvite,
                "room.messages" => WorkerMethod.RoomMessages,
                "room.send_text" => WorkerMethod.RoomSendText,
                "peer_verification.start" => WorkerMethod.PeerVerificationStart,
                "peer_verification.status" => WorkerMethod.PeerVerificationStatus,
                "peer_verification.confirm" => WorkerMethod.PeerVerificationConfirm,
                "peer_verification.cancel" => WorkerMethod.PeerVerificationCancel,
                _ => (WorkerMethod?)null,
            };

            if (method is null)
            {
                return RequestParseResult.Failure(WorkerErrorCode.UnknownMethod, requestId);
            }

            if (!ValidateRequestPayload(method.Value, payloadElement))
            {
                return RequestParseResult.Failure(WorkerErrorCode.InvalidPayload, requestId);
            }

            return RequestParseResult.Success(new WorkerRequest(requestId, method.Value, payloadElement.Clone()));
        }
        catch (JsonException)
        {
            return RequestParseResult.Failure(WorkerErrorCode.MalformedRequest);
        }
        finally
        {
            if (frameCopy is not null)
            {
                CryptographicOperations.ZeroMemory(frameCopy);
            }
        }
    }

    private static bool ValidateRequestPayload(WorkerMethod method, JsonElement payload)
    {
        if (HasDuplicateProperties(payload))
        {
            return false;
        }

        return method switch
        {
            WorkerMethod.Hello or WorkerMethod.PrivacyStatus or WorkerMethod.TorStatus or
                WorkerMethod.MatrixLogout or WorkerMethod.RoomsList or WorkerMethod.InvitesList => HasExactProperties(payload),
            WorkerMethod.MatrixLogin => HasStringProperties(payload, "homeserver", "username", "password", "storePassphrase", "storeId"),
            WorkerMethod.MatrixRestore => HasExactProperties(payload, "homeserver", "session", "storePassphrase", "storeId") &&
                IsString(payload, "homeserver") && payload.GetProperty("session").ValueKind == JsonValueKind.Object &&
                IsString(payload, "storePassphrase") && IsString(payload, "storeId"),
            WorkerMethod.RoomCreateDirect => HasStringProperties(payload, "userId"),
            WorkerMethod.RoomAcceptInvite => HasStringProperties(payload, "roomId"),
            WorkerMethod.RoomMessages => HasStringProperties(payload, "roomId"),
            WorkerMethod.RoomSendText => HasStringProperties(payload, "roomId", "body"),
            WorkerMethod.PeerVerificationStart => HasExactProperties(payload, "peerUserId") &&
                IsBoundedString(payload, "peerUserId", 255),
            WorkerMethod.PeerVerificationStatus or WorkerMethod.PeerVerificationConfirm or WorkerMethod.PeerVerificationCancel =>
                HasExactProperties(payload, "peerUserId", "flowId") &&
                IsBoundedString(payload, "peerUserId", 255) && IsBoundedString(payload, "flowId", 255),
            _ => false,
        };
    }

    private static bool IsBoundedString(JsonElement element, string name, int maxUtf8Bytes) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
        value.GetString() is { Length: > 0 } text && Encoding.UTF8.GetByteCount(text) <= maxUtf8Bytes;

    private static bool HasStringProperties(JsonElement element, params string[] names) =>
        HasExactProperties(element, names) && names.All(name => IsString(element, name));

    private static bool IsString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String;

    private static bool IsBoolean(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False;

    private static bool IsPeerIdentityStatus(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        return element.GetString() is "unknown" or "unverified" or "verified" or "previously_verified" or "verification_violation";
    }

    private static bool HasDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!seen.Add(property.Name) || HasDuplicateProperties(property.Value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            return element.EnumerateArray().Any(HasDuplicateProperties);
        }

        return false;
    }

    public static WorkerResponseParseResult ParseResponse(ReadOnlySpan<byte> frame)
    {
        if (frame.Length > MaxFrameBytes)
        {
            return WorkerResponseParseResult.Failure(WorkerErrorCode.FrameTooLarge);
        }

        if (frame.IsEmpty)
        {
            return WorkerResponseParseResult.Failure(WorkerErrorCode.MalformedRequest);
        }

        byte[]? frameCopy = null;
        try
        {
            frameCopy = frame.ToArray();
            using var document = JsonDocument.Parse(frameCopy, new JsonDocumentOptions
            {
                MaxDepth = MaxJsonDepth,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
            });

            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !HasExactProperties(root, "v", "kind", "id", "ok", "result", "error"))
            {
                return WorkerResponseParseResult.Failure(WorkerErrorCode.InvalidRequest);
            }

            if (!root.TryGetProperty("v", out var versionElement) ||
                versionElement.ValueKind != JsonValueKind.Number ||
                !versionElement.TryGetInt32(out var version))
            {
                return WorkerResponseParseResult.Failure(WorkerErrorCode.InvalidRequest);
            }

            if (version != CurrentVersion)
            {
                return WorkerResponseParseResult.Failure(WorkerErrorCode.UnsupportedVersion);
            }

            if (root.GetProperty("kind").ValueKind != JsonValueKind.String ||
                root.GetProperty("kind").GetString() != "response" ||
                root.GetProperty("ok").ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return WorkerResponseParseResult.Failure(WorkerErrorCode.InvalidRequest);
            }

            Guid? requestId = null;
            var idElement = root.GetProperty("id");
            if (idElement.ValueKind != JsonValueKind.Null)
            {
                if (idElement.ValueKind != JsonValueKind.String ||
                    !Guid.TryParseExact(idElement.GetString(), "D", out var parsedId) ||
                    parsedId == Guid.Empty)
                {
                    return WorkerResponseParseResult.Failure(WorkerErrorCode.InvalidRequest);
                }

                requestId = parsedId;
            }

            if (root.GetProperty("ok").GetBoolean())
            {
                if (requestId is null ||
                    root.GetProperty("error").ValueKind != JsonValueKind.Null ||
                    !root.TryGetProperty("result", out var result) ||
                    result.ValueKind != JsonValueKind.Object || HasDuplicateProperties(result))
                {
                    return WorkerResponseParseResult.Failure(WorkerErrorCode.InvalidRequest);
                }

                if (HasExactProperties(result, "protocolVersion") &&
                    result.GetProperty("protocolVersion").ValueKind == JsonValueKind.Number &&
                    result.GetProperty("protocolVersion").TryGetInt32(out var protocolVersion))
                {
                    return WorkerResponseParseResult.Success(new WorkerResponse(
                        requestId, WorkerResponseKind.Hello, null, protocolVersion));
                }

                if (HasExactProperties(result, "state", "networkAccess", "e2ee", "tor") &&
                    result.EnumerateObject().All(property => property.Value.ValueKind == JsonValueKind.String))
                {
                    return WorkerResponseParseResult.Success(new WorkerResponse(
                        requestId,
                        WorkerResponseKind.PrivacyStatus,
                        null,
                        PrivacyState: result.GetProperty("state").GetString(),
                        NetworkAccess: result.GetProperty("networkAccess").GetString(),
                        ResultPayload: result.Clone()));
                }

                return WorkerResponseParseResult.Success(new WorkerResponse(
                    requestId, WorkerResponseKind.Generic, null, ResultPayload: result.Clone()));
            }

            if (root.GetProperty("result").ValueKind != JsonValueKind.Null ||
                !root.TryGetProperty("error", out var error) || error.ValueKind != JsonValueKind.Object ||
                !HasExactProperties(error, "code") || error.GetProperty("code").ValueKind != JsonValueKind.String)
            {
                return WorkerResponseParseResult.Failure(WorkerErrorCode.InvalidRequest);
            }

            var errorCode = ParseErrorCode(error.GetProperty("code").GetString());
            return errorCode is null
                ? WorkerResponseParseResult.Failure(WorkerErrorCode.InvalidRequest)
                : WorkerResponseParseResult.Success(WorkerResponse.Failure(requestId, errorCode.Value));
        }
        catch (JsonException)
        {
            return WorkerResponseParseResult.Failure(WorkerErrorCode.MalformedRequest);
        }
        finally
        {
            if (frameCopy is not null)
            {
                CryptographicOperations.ZeroMemory(frameCopy);
            }
        }
    }

    internal static bool IsExpectedResponsePayload(WorkerMethod method, WorkerResponse response)
    {
        if (method == WorkerMethod.Hello)
        {
            return response.Result == WorkerResponseKind.Hello && response.ProtocolVersion == CurrentVersion;
        }

        if (method == WorkerMethod.PrivacyStatus)
        {
            return response.Result == WorkerResponseKind.PrivacyStatus &&
                response.PrivacyState == "matrix_sdk_available" &&
                response.NetworkAccess == "tor_required" &&
                response.ResultPayload is { } privacy &&
                privacy.GetProperty("e2ee").GetString() == "sdk_feature_available" &&
                privacy.GetProperty("tor").GetString() == "not_checked";
        }

        if (response.Result != WorkerResponseKind.Generic || response.ResultPayload is not { } payload ||
            HasDuplicateProperties(payload))
        {
            return false;
        }

        return method switch
        {
            WorkerMethod.TorStatus => HasExactProperties(payload, "state", "networkOperationsAllowed") &&
                payload.GetProperty("state").ValueKind == JsonValueKind.String &&
                payload.GetProperty("state").GetString() is "bootstrap_verified" or "configured_not_started" or "not_configured" or "not_ready" &&
                IsBoolean(payload, "networkOperationsAllowed") &&
                payload.GetProperty("networkOperationsAllowed").GetBoolean() ==
                    (payload.GetProperty("state").GetString() == "bootstrap_verified"),
            WorkerMethod.MatrixLogin => HasExactProperties(payload, "userId", "session", "e2eeAvailable") &&
                IsString(payload, "userId") && payload.GetProperty("session").ValueKind == JsonValueKind.Object &&
                payload.GetProperty("e2eeAvailable").ValueKind == JsonValueKind.True,
            WorkerMethod.MatrixRestore => HasExactProperties(payload, "userId", "e2eeAvailable") &&
                IsString(payload, "userId") && payload.GetProperty("e2eeAvailable").ValueKind == JsonValueKind.True,
            WorkerMethod.MatrixLogout => HasExactProperties(payload, "loggedOut") &&
                payload.GetProperty("loggedOut").ValueKind == JsonValueKind.True,
            WorkerMethod.RoomsList => HasExactProperties(payload, "rooms") &&
                payload.GetProperty("rooms").ValueKind == JsonValueKind.Array &&
                payload.GetProperty("rooms").EnumerateArray().All(room =>
                    HasExactProperties(room, "roomId", "encrypted", "encryptionKnown", "peerUserId", "peerIdentityStatus") &&
                    IsString(room, "roomId") && IsString(room, "peerUserId") && IsPeerIdentityStatus(room.GetProperty("peerIdentityStatus")) &&
                    room.GetProperty("encrypted").ValueKind == JsonValueKind.True &&
                    room.GetProperty("encryptionKnown").ValueKind == JsonValueKind.True),
            WorkerMethod.InvitesList => HasExactProperties(payload, "invites") &&
                payload.GetProperty("invites").ValueKind == JsonValueKind.Array &&
                payload.GetProperty("invites").EnumerateArray().All(invite =>
                    HasExactProperties(invite, "roomId", "isDirect", "encrypted", "encryptionKnown") &&
                    IsString(invite, "roomId") && IsBoolean(invite, "isDirect") &&
                    IsBoolean(invite, "encrypted") && IsBoolean(invite, "encryptionKnown")),
            WorkerMethod.RoomCreateDirect => HasExactProperties(payload, "roomId", "encrypted") &&
                IsString(payload, "roomId") && IsBoolean(payload, "encrypted"),
            WorkerMethod.RoomAcceptInvite => HasExactProperties(payload, "roomId", "encrypted", "encryptionKnown") &&
                IsString(payload, "roomId") && payload.GetProperty("encrypted").ValueKind == JsonValueKind.True &&
                payload.GetProperty("encryptionKnown").ValueKind == JsonValueKind.True,
            WorkerMethod.RoomMessages => HasExactProperties(payload, "roomId", "encrypted", "events") &&
                IsString(payload, "roomId") && payload.GetProperty("encrypted").ValueKind == JsonValueKind.True &&
                payload.GetProperty("events").ValueKind == JsonValueKind.Array &&
                payload.GetProperty("events").EnumerateArray().All(message =>
                    HasExactProperties(message, "eventId", "sender", "body") && IsString(message, "sender") &&
                    message.GetProperty("eventId").ValueKind is JsonValueKind.String or JsonValueKind.Null && IsString(message, "body")),
            WorkerMethod.RoomSendText => HasExactProperties(payload, "sent", "encrypted") &&
                payload.GetProperty("sent").ValueKind == JsonValueKind.True &&
                payload.GetProperty("encrypted").ValueKind == JsonValueKind.True,
            WorkerMethod.PeerVerificationStart or WorkerMethod.PeerVerificationStatus =>
                IsPeerVerificationResult(payload),
            WorkerMethod.PeerVerificationConfirm => HasExactProperties(payload, "confirmed") &&
                payload.GetProperty("confirmed").ValueKind == JsonValueKind.True,
            WorkerMethod.PeerVerificationCancel => HasExactProperties(payload, "cancelled") &&
                payload.GetProperty("cancelled").ValueKind == JsonValueKind.True,
            _ => false,
        };
    }

    private static bool IsPeerVerificationResult(JsonElement payload)
    {
        if (!HasExactProperties(payload, "peerUserId", "flowId", "state", "emojis", "decimals", "identityStatus") ||
            !IsBoundedString(payload, "peerUserId", 255) || !IsBoundedString(payload, "flowId", 255) ||
            !IsString(payload, "state") || !IsPeerIdentityStatus(payload.GetProperty("identityStatus")) ||
            payload.GetProperty("state").GetString() is not ("waiting" or "sas_ready" or "confirming" or "completed" or "cancelled"))
        {
            return false;
        }

        var emojis = payload.GetProperty("emojis");
        if (emojis.ValueKind != JsonValueKind.Array || emojis.GetArrayLength() is not (0 or 7) ||
            !emojis.EnumerateArray().All(emoji =>
                HasExactProperties(emoji, "symbol", "description") && IsString(emoji, "symbol") &&
                IsString(emoji, "description")))
        {
            return false;
        }

        var decimals = payload.GetProperty("decimals");
        if (decimals.ValueKind != JsonValueKind.Array || decimals.GetArrayLength() is not (0 or 3) ||
            !decimals.EnumerateArray().All(value => value.ValueKind == JsonValueKind.Number &&
                value.TryGetInt32(out var number) && number is >= 0 and <= 999))
        {
            return false;
        }

        return payload.GetProperty("state").GetString() != "sas_ready" ||
            emojis.GetArrayLength() == 7 || decimals.GetArrayLength() == 3;
    }

    public static WorkerResponse Dispatch(WorkerRequest request) =>
        request.Method switch
        {
            WorkerMethod.Hello => WorkerResponse.Success(request.Id, WorkerResponseKind.Hello),
            WorkerMethod.PrivacyStatus => WorkerResponse.Success(request.Id, WorkerResponseKind.PrivacyStatus),
            _ => WorkerResponse.Failure(request.Id, WorkerErrorCode.OperationFailed),
        };

    public static byte[] SerializeRequestFrame(WorkerRequest request)
    {
        if (request.Id == Guid.Empty)
        {
            throw new ArgumentException("A non-empty request ID is required.", nameof(request));
        }

        var method = MethodName(request.Method);
        var payload = request.Payload.ValueKind == JsonValueKind.Undefined
            ? JsonSerializer.SerializeToElement(new { }, SerializerOptions)
            : request.Payload;

        var json = JsonSerializer.SerializeToUtf8Bytes(new
        {
            v = CurrentVersion,
            kind = "request",
            id = request.Id,
            method,
            payload,
        }, SerializerOptions);

        return AddNewline(json);
    }

    public static byte[] SerializeResponseFrame(WorkerResponse response)
    {
        if (response.Result is not null && !Enum.IsDefined(response.Result.Value))
        {
            return SerializeErrorFrame(response.RequestId, WorkerErrorCode.InternalError);
        }

        var isValidSuccess = response.Result is not null && response.ErrorCode is null;
        var isValidError = response.Result is null && response.ErrorCode is not null;
        if (!isValidSuccess && !isValidError)
        {
            return SerializeErrorFrame(response.RequestId, WorkerErrorCode.InternalError);
        }

        object? result = response.Result switch
        {
            WorkerResponseKind.Hello => new { protocolVersion = response.ProtocolVersion ?? CurrentVersion },
            WorkerResponseKind.PrivacyStatus => new
            {
                state = response.PrivacyState ?? "matrix_sdk_available",
                networkAccess = response.NetworkAccess ?? "tor_required",
                e2ee = "sdk_feature_available",
                tor = "not_checked",
            },
            WorkerResponseKind.Generic => response.ResultPayload ?? JsonSerializer.SerializeToElement(new { }, SerializerOptions),
            null => null,
            _ => null,
        };

        var error = response.ErrorCode is null
            ? null
            : new WireError(ErrorCodeName(response.ErrorCode.Value));

        var json = JsonSerializer.SerializeToUtf8Bytes(
            new WireResponse(CurrentVersion, "response", response.RequestId, isValidSuccess, result, error),
            SerializerOptions);

        if (json.Length > MaxFrameBytes)
        {
            return SerializeErrorFrame(response.RequestId, WorkerErrorCode.OutputTooLarge);
        }

        return AddNewline(json);
    }

    private static byte[] SerializeErrorFrame(Guid? requestId, WorkerErrorCode errorCode)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(
            new WireResponse(
                CurrentVersion,
                "response",
                requestId,
                false,
                null,
                new WireError(ErrorCodeName(errorCode))),
            SerializerOptions);

        // Error envelopes contain only fixed strings and an optional UUID, so this
        // bounded fallback is smaller than the protocol frame limit by construction.
        return AddNewline(json);
    }

    private static byte[] AddNewline(byte[] json)
    {
        if (json.Length > MaxFrameBytes)
        {
            throw new InvalidOperationException("The fixed worker IPC envelope exceeded its frame limit.");
        }

        var frame = new byte[json.Length + 1];
        json.CopyTo(frame, 0);
        frame[^1] = (byte)'\n';
        return frame;
    }

    private static string ErrorCodeName(WorkerErrorCode errorCode) => errorCode switch
    {
        WorkerErrorCode.InvalidRequest => "INVALID_REQUEST",
        WorkerErrorCode.MalformedRequest => "MALFORMED_REQUEST",
        WorkerErrorCode.FrameTooLarge => "FRAME_TOO_LARGE",
        WorkerErrorCode.TruncatedFrame => "TRUNCATED_FRAME",
        WorkerErrorCode.UnsupportedVersion => "UNSUPPORTED_VERSION",
        WorkerErrorCode.UnknownMethod => "UNKNOWN_METHOD",
        WorkerErrorCode.OutputTooLarge => "OUTPUT_TOO_LARGE",
        WorkerErrorCode.Cancelled => "CANCELLED",
        WorkerErrorCode.WorkerUnavailable => "WORKER_UNAVAILABLE",
        WorkerErrorCode.TorNotConfigured => "TOR_NOT_CONFIGURED",
        WorkerErrorCode.TorNotReady => "TOR_NOT_READY",
        WorkerErrorCode.AuthenticationFailed => "AUTHENTICATION_FAILED",
        WorkerErrorCode.DirectMessageRequired => "DIRECT_MESSAGE_REQUIRED",
        WorkerErrorCode.EncryptionRequired => "ENCRYPTION_REQUIRED",
        WorkerErrorCode.VerificationUnavailable => "VERIFICATION_UNAVAILABLE",
        WorkerErrorCode.NotLoggedIn => "NOT_LOGGED_IN",
        WorkerErrorCode.OperationFailed => "OPERATION_FAILED",
        WorkerErrorCode.InvalidPayload => "INVALID_PAYLOAD",
        WorkerErrorCode.InternalError => "INTERNAL_ERROR",
        _ => "INTERNAL_ERROR",
    };

    private static WorkerErrorCode? ParseErrorCode(string? errorCode) => errorCode switch
    {
        "INVALID_REQUEST" => WorkerErrorCode.InvalidRequest,
        "MALFORMED_REQUEST" => WorkerErrorCode.MalformedRequest,
        "FRAME_TOO_LARGE" => WorkerErrorCode.FrameTooLarge,
        "TRUNCATED_FRAME" => WorkerErrorCode.TruncatedFrame,
        "UNSUPPORTED_VERSION" => WorkerErrorCode.UnsupportedVersion,
        "UNKNOWN_METHOD" => WorkerErrorCode.UnknownMethod,
        "OUTPUT_TOO_LARGE" => WorkerErrorCode.OutputTooLarge,
        "CANCELLED" => WorkerErrorCode.Cancelled,
        "WORKER_UNAVAILABLE" => WorkerErrorCode.WorkerUnavailable,
        "TOR_NOT_CONFIGURED" => WorkerErrorCode.TorNotConfigured,
        "TOR_NOT_READY" => WorkerErrorCode.TorNotReady,
        "AUTHENTICATION_FAILED" => WorkerErrorCode.AuthenticationFailed,
        "DIRECT_MESSAGE_REQUIRED" => WorkerErrorCode.DirectMessageRequired,
        "ENCRYPTION_REQUIRED" => WorkerErrorCode.EncryptionRequired,
        "VERIFICATION_UNAVAILABLE" => WorkerErrorCode.VerificationUnavailable,
        "NOT_LOGGED_IN" => WorkerErrorCode.NotLoggedIn,
        "OPERATION_FAILED" => WorkerErrorCode.OperationFailed,
        "INVALID_PAYLOAD" => WorkerErrorCode.InvalidPayload,
        "INTERNAL_ERROR" => WorkerErrorCode.InternalError,
        _ => null,
    };

    private static string MethodName(WorkerMethod method) => method switch
    {
        WorkerMethod.Hello => "worker.hello",
        WorkerMethod.PrivacyStatus => "privacy.status",
        WorkerMethod.TorStatus => "tor.status",
        WorkerMethod.MatrixLogin => "matrix.login",
        WorkerMethod.MatrixRestore => "matrix.restore",
        WorkerMethod.MatrixLogout => "matrix.logout",
        WorkerMethod.RoomsList => "rooms.list",
        WorkerMethod.InvitesList => "invites.list",
        WorkerMethod.RoomCreateDirect => "room.create_dm",
        WorkerMethod.RoomAcceptInvite => "room.accept_invite",
        WorkerMethod.RoomMessages => "room.messages",
        WorkerMethod.RoomSendText => "room.send_text",
        WorkerMethod.PeerVerificationStart => "peer_verification.start",
        WorkerMethod.PeerVerificationStatus => "peer_verification.status",
        WorkerMethod.PeerVerificationConfirm => "peer_verification.confirm",
        WorkerMethod.PeerVerificationCancel => "peer_verification.cancel",
        _ => throw new ArgumentOutOfRangeException(nameof(method)),
    };

    private static bool HasExactProperties(JsonElement element, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var expectedProperties = new HashSet<string>(expected, StringComparer.Ordinal);
        var seenProperties = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!expectedProperties.Contains(property.Name) || !seenProperties.Add(property.Name))
            {
                return false;
            }
        }

        return seenProperties.Count == expectedProperties.Count;
    }


    private sealed record WireError(string Code);

    private sealed record WireResponse(
        int V,
        string Kind,
        Guid? Id,
        bool Ok,
        object? Result,
        WireError? Error);
}

/// <summary>
/// Reads bounded newline-delimited UTF-8 frames without allocating based on an
/// untrusted line length. The reader retains bytes after a newline for the next call.
/// </summary>
public sealed class WorkerFrameReader
{
    private const int ReadBufferSize = 4096;

    private readonly Stream _stream;
    private readonly byte[] _readBuffer = new byte[ReadBufferSize];
    private int _readOffset;
    private int _readCount;

    public WorkerFrameReader(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
        {
            throw new ArgumentException("The worker IPC stream must be readable.", nameof(stream));
        }

        _stream = stream;
    }

    internal bool HasBufferedBytes => _readOffset < _readCount;

    public async ValueTask<byte[]?> ReadFrameAsync(CancellationToken cancellationToken = default)
    {
        using var frame = new MemoryStream(capacity: 1024);
        var sawData = false;

        while (true)
        {
            if (_readOffset == _readCount)
            {
                _readCount = await _stream.ReadAsync(_readBuffer.AsMemory(), cancellationToken)
                    .ConfigureAwait(false);
                _readOffset = 0;

                if (_readCount == 0)
                {
                    if (!sawData)
                    {
                        return null;
                    }

                    throw new WorkerFrameException(WorkerErrorCode.TruncatedFrame);
                }
            }

            var current = _readBuffer[_readOffset++];
            if (current == (byte)'\n')
            {
                var bytes = frame.ToArray();
                if (bytes.Length > 0 && bytes[^1] == (byte)'\r')
                {
                    Array.Resize(ref bytes, bytes.Length - 1);
                }

                return bytes;
            }

            sawData = true;
            if (frame.Length == WorkerProtocol.MaxFrameBytes)
            {
                throw new WorkerFrameException(WorkerErrorCode.FrameTooLarge);
            }

            frame.WriteByte(current);
        }
    }
}
