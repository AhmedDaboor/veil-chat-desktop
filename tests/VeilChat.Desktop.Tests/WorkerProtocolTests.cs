using System.Text;
using System.Text.Json;
using VeilChat.Desktop.Core.Ipc;
using Xunit;

namespace VeilChat.Desktop.Tests;

public sealed class WorkerProtocolTests
{
    private static readonly Guid RequestId = Guid.Parse("d41c435b-24c8-458a-b873-3ca1d77c2c34");

    [Fact]
    public void HelloRequestUsesVersionedTypedEnvelopeAndReturnsProtocolVersion()
    {
        var frame = WorkerProtocol.SerializeRequestFrame(new WorkerRequest(RequestId, WorkerMethod.Hello));
        var parsed = WorkerProtocol.ParseRequest(frame.AsSpan(0, frame.Length - 1));

        Assert.True(parsed.IsSuccess);
        Assert.Equal(RequestId, parsed.Request!.Id);
        Assert.Equal(WorkerMethod.Hello, parsed.Request.Method);

        var response = WorkerProtocol.Dispatch(parsed.Request);
        var responseJson = Encoding.UTF8.GetString(WorkerProtocol.SerializeResponseFrame(response));
        Assert.Contains("\"v\":2", responseJson, StringComparison.Ordinal);
        Assert.Contains("\"protocolVersion\":2", responseJson, StringComparison.Ordinal);
        Assert.Contains(RequestId.ToString("D"), responseJson, StringComparison.Ordinal);
        Assert.EndsWith("\n", responseJson, StringComparison.Ordinal);
    }

    [Fact]
    public void PrivacyStatusDistinguishesSdkSupportFromTorReadiness()
    {
        var response = WorkerProtocol.Dispatch(new WorkerRequest(RequestId, WorkerMethod.PrivacyStatus));
        var json = Encoding.UTF8.GetString(WorkerProtocol.SerializeResponseFrame(response));

        Assert.Contains("\"state\":\"matrix_sdk_available\"", json, StringComparison.Ordinal);
        Assert.Contains("\"networkAccess\":\"tor_required\"", json, StringComparison.Ordinal);
        Assert.Contains("\"e2ee\":\"sdk_feature_available\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void UnsupportedVersionReturnsSafeErrorAndPreservesCorrelationId()
    {
        var parsed = WorkerProtocol.ParseRequest(Encoding.UTF8.GetBytes(
            $"{{\"v\":3,\"kind\":\"request\",\"id\":\"{RequestId:D}\",\"method\":\"worker.hello\",\"payload\":{{}}}}"));

        Assert.False(parsed.IsSuccess);
        Assert.Equal(WorkerErrorCode.UnsupportedVersion, parsed.ErrorCode);
        Assert.Equal(RequestId, parsed.RequestId);
    }

    [Fact]
    public void UnknownMethodIsRejectedWithoutEchoingUntrustedText()
    {
        const string untrustedMethod = "DO_NOT_ECHO_THIS_MARKER";
        var parsed = WorkerProtocol.ParseRequest(Encoding.UTF8.GetBytes(
            $"{{\"v\":2,\"kind\":\"request\",\"id\":\"{RequestId:D}\",\"method\":\"{untrustedMethod}\",\"payload\":{{}}}}"));

        Assert.Equal(WorkerErrorCode.UnknownMethod, parsed.ErrorCode);
        var errorFrame = WorkerProtocol.SerializeResponseFrame(
            WorkerResponse.Failure(parsed.RequestId, parsed.ErrorCode!.Value));
        Assert.DoesNotContain(untrustedMethod, Encoding.UTF8.GetString(errorFrame), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"v\":")]
    [InlineData("[]")]
    public void MalformedOrWrongRootInputIsRejected(string input)
    {
        var parsed = WorkerProtocol.ParseRequest(Encoding.UTF8.GetBytes(input));

        Assert.False(parsed.IsSuccess);
        Assert.NotNull(parsed.ErrorCode);
    }

    [Fact]
    public void DuplicateAndUnknownEnvelopePropertiesAreRejected()
    {
        var duplicate = $"{{\"v\":2,\"v\":2,\"kind\":\"request\",\"id\":\"{RequestId:D}\",\"method\":\"worker.hello\",\"payload\":{{}}}}";
        var extra = $"{{\"v\":2,\"kind\":\"request\",\"id\":\"{RequestId:D}\",\"method\":\"worker.hello\",\"payload\":{{}},\"message\":\"DO_NOT_ECHO_THIS_MARKER\"}}";

        Assert.Equal(WorkerErrorCode.InvalidRequest, WorkerProtocol.ParseRequest(Encoding.UTF8.GetBytes(duplicate)).ErrorCode);
        Assert.Equal(WorkerErrorCode.InvalidRequest, WorkerProtocol.ParseRequest(Encoding.UTF8.GetBytes(extra)).ErrorCode);
    }

    [Fact]
    public void EmptyPayloadMethodsRejectUnexpectedFields()
    {
        var input = $"{{\"v\":2,\"kind\":\"request\",\"id\":\"{RequestId:D}\",\"method\":\"worker.hello\",\"payload\":{{\"body\":\"DO_NOT_ECHO_THIS_MARKER\"}}}}";

        Assert.Equal(WorkerErrorCode.InvalidPayload, WorkerProtocol.ParseRequest(Encoding.UTF8.GetBytes(input)).ErrorCode);
    }

    [Fact]
    public void MatrixLoginUsesItsReviewedV2PayloadShape()
    {
        var payload = JsonSerializer.SerializeToElement(new
        {
            homeserver = "https://example.org",
            username = "alice",
            password = "DO_NOT_ECHO_THIS_SECRET",
            storePassphrase = "secret-store-key",
            storeId = "a34585cf-3381-4fdd-a122-945360e3878c",
        });
        var frame = WorkerProtocol.SerializeRequestFrame(new WorkerRequest(RequestId, WorkerMethod.MatrixLogin, payload));
        var parsed = WorkerProtocol.ParseRequest(frame.AsSpan(0, frame.Length - 1));

        Assert.True(parsed.IsSuccess);
        Assert.Equal(WorkerMethod.MatrixLogin, parsed.Request!.Method);

        var duplicate = $"{{\"v\":2,\"kind\":\"request\",\"id\":\"{RequestId:D}\",\"method\":\"matrix.login\",\"payload\":{{\"homeserver\":\"https://example.org\",\"username\":\"alice\",\"username\":\"mallory\",\"password\":\"x\",\"storePassphrase\":\"y\",\"storeId\":\"a34585cf-3381-4fdd-a122-945360e3878c\"}}}}";
        Assert.Equal(WorkerErrorCode.InvalidRequest, WorkerProtocol.ParseRequest(Encoding.UTF8.GetBytes(duplicate)).ErrorCode);
    }

    [Fact]
    public void InvitationCommandsUseStrictTypedPayloads()
    {
        var listFrame = WorkerProtocol.SerializeRequestFrame(new WorkerRequest(
            RequestId,
            WorkerMethod.InvitesList,
            JsonSerializer.SerializeToElement(new { })));
        var acceptFrame = WorkerProtocol.SerializeRequestFrame(new WorkerRequest(
            RequestId,
            WorkerMethod.RoomAcceptInvite,
            JsonSerializer.SerializeToElement(new { roomId = "!room:example.org" })));

        var list = WorkerProtocol.ParseRequest(listFrame.AsSpan(0, listFrame.Length - 1));
        var accept = WorkerProtocol.ParseRequest(acceptFrame.AsSpan(0, acceptFrame.Length - 1));

        Assert.True(list.IsSuccess);
        Assert.Equal(WorkerMethod.InvitesList, list.Request!.Method);
        Assert.True(accept.IsSuccess);
        Assert.Equal(WorkerMethod.RoomAcceptInvite, accept.Request!.Method);
        Assert.Equal(
            WorkerErrorCode.InvalidPayload,
            WorkerProtocol.ParseRequest(Encoding.UTF8.GetBytes(
                $"{{\"v\":2,\"kind\":\"request\",\"id\":\"{RequestId:D}\",\"method\":\"room.accept_invite\",\"payload\":{{\"roomId\":\"!room:example.org\",\"force\":true}}}}"))
                .ErrorCode);
    }

    [Fact]
    public void PeerVerificationRequestsAndSasResponsesAreStrictlyTyped()
    {
        var requestPayloads = new (WorkerMethod Method, object Payload)[]
        {
            (WorkerMethod.PeerVerificationStart, new { peerUserId = "@peer:example.org" }),
            (WorkerMethod.PeerVerificationStatus, new { peerUserId = "@peer:example.org", flowId = "flow-123" }),
            (WorkerMethod.PeerVerificationConfirm, new { peerUserId = "@peer:example.org", flowId = "flow-123" }),
            (WorkerMethod.PeerVerificationCancel, new { peerUserId = "@peer:example.org", flowId = "flow-123" }),
        };

        foreach (var (method, payload) in requestPayloads)
        {
            var frame = WorkerProtocol.SerializeRequestFrame(new WorkerRequest(
                RequestId,
                method,
                JsonSerializer.SerializeToElement(payload)));
            Assert.True(WorkerProtocol.ParseRequest(frame.AsSpan(0, frame.Length - 1)).IsSuccess);
        }

        var invalid = WorkerProtocol.SerializeRequestFrame(new WorkerRequest(
            RequestId,
            WorkerMethod.PeerVerificationStatus,
            JsonSerializer.SerializeToElement(new { peerUserId = "@peer:example.org", flowId = "" })));
        Assert.Equal(WorkerErrorCode.InvalidPayload,
            WorkerProtocol.ParseRequest(invalid.AsSpan(0, invalid.Length - 1)).ErrorCode);

        using var validResult = JsonDocument.Parse("""
            {"peerUserId":"@peer:example.org","flowId":"flow-123","state":"sas_ready","emojis":[
              {"symbol":"🐶","description":"Dog"},{"symbol":"🐱","description":"Cat"},
              {"symbol":"🐭","description":"Mouse"},{"symbol":"🐹","description":"Hamster"},
              {"symbol":"🐰","description":"Rabbit"},{"symbol":"🦊","description":"Fox"},
              {"symbol":"🐻","description":"Bear"}],"decimals":[123,456,789],"identityStatus":"unverified"}
            """);
        using var malformedResult = JsonDocument.Parse("""
            {"peerUserId":"@peer:example.org","flowId":"flow-123","state":"verified",
             "emojis":[],"decimals":[],"identityStatus":"trusted"}
            """);
        var validEnvelope = WorkerProtocol.SerializeResponseFrame(new WorkerResponse(
            RequestId,
            WorkerResponseKind.Generic,
            null,
            ResultPayload: validResult.RootElement.Clone()));
        var invalidEnvelope = WorkerProtocol.SerializeResponseFrame(new WorkerResponse(
            RequestId,
            WorkerResponseKind.Generic,
            null,
            ResultPayload: malformedResult.RootElement.Clone()));
        Assert.True(WorkerProtocol.ParseResponse(validEnvelope).IsSuccess);
        Assert.True(WorkerProtocol.ParseResponse(invalidEnvelope).IsSuccess);
    }

    [Fact]
    public void ParserRejectsFramesOverTheByteLimit()
    {
        var oversized = new byte[WorkerProtocol.MaxFrameBytes + 1];

        var parsed = WorkerProtocol.ParseRequest(oversized);

        Assert.Equal(WorkerErrorCode.FrameTooLarge, parsed.ErrorCode);
    }

    [Fact]
    public async Task FrameReaderHandlesMultipleFramesAndCrLf()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("first\r\nsecond\n"));
        var reader = new WorkerFrameReader(stream);

        Assert.Equal("first", Encoding.UTF8.GetString((await reader.ReadFrameAsync())!));
        Assert.Equal("second", Encoding.UTF8.GetString((await reader.ReadFrameAsync())!));
        Assert.Null(await reader.ReadFrameAsync());
    }

    [Fact]
    public async Task FrameReaderAcceptsLimitAndRejectsTheNextByte()
    {
        var maxLengthFrame = new byte[WorkerProtocol.MaxFrameBytes + 1];
        Array.Fill(maxLengthFrame, (byte)'x', 0, WorkerProtocol.MaxFrameBytes);
        maxLengthFrame[^1] = (byte)'\n';
        using var acceptedStream = new MemoryStream(maxLengthFrame);
        var accepted = await new WorkerFrameReader(acceptedStream).ReadFrameAsync();
        Assert.Equal(WorkerProtocol.MaxFrameBytes, accepted!.Length);

        var tooLongFrame = new byte[WorkerProtocol.MaxFrameBytes + 2];
        Array.Fill(tooLongFrame, (byte)'x', 0, WorkerProtocol.MaxFrameBytes + 1);
        tooLongFrame[^1] = (byte)'\n';
        using var rejectedStream = new MemoryStream(tooLongFrame);
        var error = await Assert.ThrowsAsync<WorkerFrameException>(async () =>
            await new WorkerFrameReader(rejectedStream).ReadFrameAsync());
        Assert.Equal(WorkerErrorCode.FrameTooLarge, error.ErrorCode);
    }

    [Fact]
    public async Task FrameReaderRejectsAnIncompleteFrameAtEndOfStream()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("partial"));
        var error = await Assert.ThrowsAsync<WorkerFrameException>(async () =>
            await new WorkerFrameReader(stream).ReadFrameAsync());

        Assert.Equal(WorkerErrorCode.TruncatedFrame, error.ErrorCode);
    }

    [Fact]
    public void EveryTypedResponseStaysWithinTheOutputFrameBound()
    {
        var responses = new[]
        {
            WorkerProtocol.Dispatch(new WorkerRequest(Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), WorkerMethod.Hello)),
            WorkerProtocol.Dispatch(new WorkerRequest(Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), WorkerMethod.PrivacyStatus)),
            WorkerResponse.Failure(null, WorkerErrorCode.InternalError),
        };

        Assert.All(responses, response =>
        {
            var frame = WorkerProtocol.SerializeResponseFrame(response);
            Assert.True(frame.Length <= WorkerProtocol.MaxFrameBytes + 1);
            Assert.Equal((byte)'\n', frame[^1]);
        });
    }

    [Fact]
    public void InvalidResponseVariantBecomesAGenericSafeError()
    {
        var invalidResponse = new WorkerResponse(RequestId, (WorkerResponseKind)999, null);

        var json = Encoding.UTF8.GetString(WorkerProtocol.SerializeResponseFrame(invalidResponse));

        Assert.Contains("\"ok\":false", json, StringComparison.Ordinal);
        Assert.Contains("\"code\":\"INTERNAL_ERROR\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("999", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ResponseParserReadsTypedHelloAndPrivacyVariants()
    {
        var helloFrame = WorkerProtocol.SerializeResponseFrame(
            WorkerProtocol.Dispatch(new WorkerRequest(RequestId, WorkerMethod.Hello)));
        var privacyFrame = WorkerProtocol.SerializeResponseFrame(
            WorkerProtocol.Dispatch(new WorkerRequest(RequestId, WorkerMethod.PrivacyStatus)));

        var hello = WorkerProtocol.ParseResponse(helloFrame);
        var privacy = WorkerProtocol.ParseResponse(privacyFrame);

        Assert.True(hello.IsSuccess);
        Assert.Equal(RequestId, hello.Response!.RequestId);
        Assert.Equal(WorkerResponseKind.Hello, hello.Response.Result);
        Assert.Equal(WorkerProtocol.CurrentVersion, hello.Response.ProtocolVersion);
        Assert.True(privacy.IsSuccess);
        Assert.Equal(WorkerResponseKind.PrivacyStatus, privacy.Response!.Result);
        Assert.Equal("matrix_sdk_available", privacy.Response.PrivacyState);
        Assert.Equal("tor_required", privacy.Response.NetworkAccess);
    }

    [Fact]
    public void ResponseParserReadsKnownErrorCodes()
    {
        foreach (var expectedCode in new[]
                 {
                     WorkerErrorCode.WorkerUnavailable,
                     WorkerErrorCode.DirectMessageRequired,
                     WorkerErrorCode.VerificationUnavailable,
                 })
        {
            var frame = WorkerProtocol.SerializeResponseFrame(
                WorkerResponse.Failure(RequestId, expectedCode));

            var parsed = WorkerProtocol.ParseResponse(frame);

            Assert.True(parsed.IsSuccess);
            Assert.Equal(RequestId, parsed.Response!.RequestId);
            Assert.Equal(expectedCode, parsed.Response.ErrorCode);
        }
    }

    [Theory]
    [InlineData("{\"v\":2")]
    [InlineData("{\"v\":2,\"kind\":\"response\",\"kind\":\"response\",\"id\":null,\"ok\":false,\"result\":null,\"error\":{\"code\":\"INTERNAL_ERROR\"}}")]
    [InlineData("{\"v\":2,\"kind\":\"response\",\"id\":null,\"ok\":false,\"result\":null,\"error\":{\"code\":\"UNKNOWN_PRIVATE_ERROR\"}}")]
    public void ResponseParserRejectsMalformedDuplicateAndUnknownErrorResponses(string input)
    {
        var parsed = WorkerProtocol.ParseResponse(Encoding.UTF8.GetBytes(input));

        Assert.False(parsed.IsSuccess);
        Assert.NotNull(parsed.ErrorCode);
    }

    [Fact]
    public void PartialPrivacyResultIsNotMisclassifiedAsTypedPrivacyStatus()
    {
        var input = $"{{\"v\":2,\"kind\":\"response\",\"id\":\"{RequestId:D}\",\"ok\":true,\"result\":{{\"state\":\"enabled\",\"networkAccess\":\"tor\"}},\"error\":null}}";

        var parsed = WorkerProtocol.ParseResponse(Encoding.UTF8.GetBytes(input));

        Assert.True(parsed.IsSuccess);
        Assert.Equal(WorkerResponseKind.Generic, parsed.Response!.Result);
    }
}
