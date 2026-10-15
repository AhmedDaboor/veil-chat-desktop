using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using System.Threading.Channels;
using VeilChat.Desktop.Core.Ipc;
using VeilChat.Desktop.Core.Services;
using Xunit;

namespace VeilChat.Desktop.Tests;

public sealed class WorkerProcessServiceTests
{
    [Fact]
    public async Task StartsOnDemandPerformsHelloAndStatusAndReusesOneWorker()
    {
        var transport = new ScriptedTransport(ReplyToEveryRequest);
        var launcher = new ScriptedLauncher(() => transport);
        await using var service = new WorkerProcessService(Options(), launcher);

        Assert.Equal(WorkerConnectionState.Stopped, service.ConnectionState);
        var first = await service.GetPrivacyStatusAsync();
        var second = await service.GetPrivacyStatusAsync();

        Assert.Equal(new WorkerPrivacyStatus("matrix_sdk_available", "tor_required", "sdk_feature_available", "not_checked"), first);
        Assert.Equal(first, second);
        Assert.Equal(WorkerConnectionState.Connected, service.ConnectionState);
        Assert.Equal(1, launcher.StartCount);
        Assert.Equal(
            [WorkerMethod.Hello, WorkerMethod.PrivacyStatus, WorkerMethod.PrivacyStatus],
            transport.Requests);
    }

    [Fact]
    public async Task ConcurrentStatusCallsAreSerializedUntilTheFirstResponseIsCorrelated()
    {
        var firstPrivacyRequest = new TaskCompletionSource<Guid>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstResponse = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var privacyRequestCount = 0;
        var transport = new ScriptedTransport(async (request, cancellationToken) =>
        {
            if (request.Method == WorkerMethod.Hello)
            {
                return Reply(request);
            }

            if (Interlocked.Increment(ref privacyRequestCount) == 1)
            {
                firstPrivacyRequest.TrySetResult(request.Id);
                await releaseFirstResponse.Task.WaitAsync(cancellationToken);
            }

            return Reply(request);
        });
        var launcher = new ScriptedLauncher(() => transport);
        await using var service = new WorkerProcessService(Options(), launcher);

        var firstRequest = service.GetPrivacyStatusAsync();
        var firstRequestId = await firstPrivacyRequest.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var secondRequest = service.GetPrivacyStatusAsync();
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        Assert.Equal(1, Volatile.Read(ref privacyRequestCount));

        releaseFirstResponse.TrySetResult(true);
        var results = await Task.WhenAll(firstRequest, secondRequest);

        Assert.All(results, result => Assert.Equal(new WorkerPrivacyStatus("matrix_sdk_available", "tor_required", "sdk_feature_available", "not_checked"), result));
        Assert.Equal(2, Volatile.Read(ref privacyRequestCount));
        Assert.Contains(transport.RequestIds, id => id == firstRequestId);
        Assert.Equal(3, transport.RequestIds.Distinct().Count());
    }

    [Fact]
    public async Task MissingConfigurationDoesNotLaunchAProcess()
    {
        var launcher = new ScriptedLauncher(() => new ScriptedTransport(ReplyToEveryRequest));
        await using var service = new WorkerProcessService(WorkerProcessOptions.Unconfigured("missing"), launcher);

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() => service.GetPrivacyStatusAsync());

        Assert.Equal(WorkerServiceFailure.NotConfigured, error.Failure);
        Assert.Equal(WorkerConnectionState.NotConfigured, service.ConnectionState);
        Assert.Equal(0, launcher.StartCount);
    }

    [Fact]
    public async Task TimeoutStopsTheWorkerAndFailsWithATypedFailure()
    {
        var transport = new ScriptedTransport(request =>
            request.Method == WorkerMethod.Hello ? Reply(request) : null);
        var launcher = new ScriptedLauncher(() => transport);
        await using var service = new WorkerProcessService(Options(TimeSpan.FromMilliseconds(120)), launcher);

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() => service.GetPrivacyStatusAsync());

        Assert.Equal(WorkerServiceFailure.RequestTimeout, error.Failure);
        Assert.True(transport.IsDisposed);
        Assert.Equal(WorkerConnectionState.Faulted, service.ConnectionState);
    }

    [Fact]
    public async Task CallerCancellationStopsTheWorkerAndPropagatesCancellation()
    {
        var transport = new ScriptedTransport(request =>
            request.Method == WorkerMethod.Hello ? Reply(request) : null);
        var launcher = new ScriptedLauncher(() => transport);
        await using var service = new WorkerProcessService(Options(TimeSpan.FromSeconds(3)), launcher);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(120));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.GetPrivacyStatusAsync(cancellation.Token));

        Assert.True(transport.IsDisposed);
        Assert.Equal(WorkerConnectionState.Faulted, service.ConnectionState);
    }

    [Fact]
    public async Task MalformedHandshakeResponseIsRejectedAndProcessIsDisposed()
    {
        var transport = new ScriptedTransport(_ => Encoding.UTF8.GetBytes("{malformed\n"));
        var launcher = new ScriptedLauncher(() => transport);
        await using var service = new WorkerProcessService(Options(), launcher);

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() => service.GetPrivacyStatusAsync());

        Assert.Equal(WorkerServiceFailure.MalformedResponse, error.Failure);
        Assert.True(transport.IsDisposed);
        Assert.Equal(WorkerConnectionState.Faulted, service.ConnectionState);
    }

    [Fact]
    public async Task ExtraBufferedWorkerOutputIsRejectedAndProcessIsDisposed()
    {
        var transport = new ScriptedTransport(request => request.Method == WorkerMethod.Hello
            ? Reply(request).Concat(Reply(request)).ToArray()
            : Reply(request));
        var launcher = new ScriptedLauncher(() => transport);
        await using var service = new WorkerProcessService(Options(), launcher);

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() => service.GetPrivacyStatusAsync());

        Assert.Equal(WorkerServiceFailure.MalformedResponse, error.Failure);
        Assert.True(transport.IsDisposed);
        Assert.Equal(WorkerConnectionState.Faulted, service.ConnectionState);
    }

    [Fact]
    public async Task MismatchedResponseIdIsRejectedAndProcessIsDisposed()
    {
        var transport = new ScriptedTransport(request => WorkerProtocol.SerializeResponseFrame(
            WorkerResponse.Success(Guid.NewGuid(), WorkerResponseKind.Hello)));
        var launcher = new ScriptedLauncher(() => transport);
        await using var service = new WorkerProcessService(Options(), launcher);

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() => service.GetPrivacyStatusAsync());

        Assert.Equal(WorkerServiceFailure.MalformedResponse, error.Failure);
        Assert.True(transport.IsDisposed);
    }

    [Fact]
    public async Task RoomListCannotExposeAnUnknownOrUnencryptedRoomForSending()
    {
        var transport = new ScriptedTransport(request => request.Method == WorkerMethod.Hello
            ? Reply(request)
            : WorkerProtocol.SerializeResponseFrame(new WorkerResponse(
                request.Id,
                WorkerResponseKind.Generic,
                null,
                ResultPayload: JsonSerializer.SerializeToElement(new
                {
                    rooms = new[]
                    {
                        new
                        {
                            roomId = "!room:example.org",
                            encrypted = false,
                            encryptionKnown = true,
                            peerUserId = "@peer:example.org",
                            peerIdentityStatus = "unverified",
                        },
                    },
                }))));
        await using var service = new WorkerProcessService(Options(), new ScriptedLauncher(() => transport));

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() =>
            service.SendCommandAsync(WorkerMethod.RoomsList, new { }));

        Assert.Equal(WorkerServiceFailure.MalformedResponse, error.Failure);
        Assert.True(transport.IsDisposed);
    }

    [Fact]
    public async Task RoomListAcceptsOnlyKnownPeerIdentityStatesAlongsideEncryptionStatus()
    {
        var transport = new ScriptedTransport(request => request.Method == WorkerMethod.Hello
            ? Reply(request)
            : WorkerProtocol.SerializeResponseFrame(new WorkerResponse(
                request.Id,
                WorkerResponseKind.Generic,
                null,
                ResultPayload: JsonSerializer.SerializeToElement(new
                {
                    rooms = new[]
                    {
                        new
                        {
                            roomId = "!room:example.org",
                            encrypted = true,
                            encryptionKnown = true,
                            peerUserId = "@peer:example.org",
                            peerIdentityStatus = "verification_violation",
                        },
                    },
                }))));
        await using var service = new WorkerProcessService(Options(), new ScriptedLauncher(() => transport));

        var result = await service.SendCommandAsync(WorkerMethod.RoomsList, new { });

        Assert.Equal("@peer:example.org", result.GetProperty("rooms")[0].GetProperty("peerUserId").GetString());
        Assert.Equal("verification_violation", result.GetProperty("rooms")[0].GetProperty("peerIdentityStatus").GetString());
    }

    [Fact]
    public async Task RoomListRejectsUnknownPeerIdentityStatusFromWorker()
    {
        var transport = new ScriptedTransport(request => request.Method == WorkerMethod.Hello
            ? Reply(request)
            : WorkerProtocol.SerializeResponseFrame(new WorkerResponse(
                request.Id,
                WorkerResponseKind.Generic,
                null,
                ResultPayload: JsonSerializer.SerializeToElement(new
                {
                    rooms = new[]
                    {
                        new
                        {
                            roomId = "!room:example.org",
                            encrypted = true,
                            encryptionKnown = true,
                            peerUserId = "@peer:example.org",
                            peerIdentityStatus = "trusted",
                        },
                    },
                }))));
        await using var service = new WorkerProcessService(Options(), new ScriptedLauncher(() => transport));

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() =>
            service.SendCommandAsync(WorkerMethod.RoomsList, new { }));

        Assert.Equal(WorkerServiceFailure.MalformedResponse, error.Failure);
        Assert.True(transport.IsDisposed);
    }

    [Fact]
    public async Task PeerVerificationAcceptsOnlyACompleteSdkSasStatus()
    {
        var payload = JsonSerializer.SerializeToElement(new
        {
            peerUserId = "@peer:example.org",
            flowId = "flow-123",
            state = "sas_ready",
            emojis = new[]
            {
                new { symbol = "🐶", description = "Dog" },
                new { symbol = "🐱", description = "Cat" },
                new { symbol = "🐭", description = "Mouse" },
                new { symbol = "🐹", description = "Hamster" },
                new { symbol = "🐰", description = "Rabbit" },
                new { symbol = "🦊", description = "Fox" },
                new { symbol = "🐻", description = "Bear" },
            },
            decimals = new[] { 123, 456, 789 },
            identityStatus = "unverified",
        });
        var transport = PeerVerificationTransport(payload);
        await using var service = new WorkerProcessService(Options(), new ScriptedLauncher(() => transport));

        var response = await service.SendCommandAsync(
            WorkerMethod.PeerVerificationStatus,
            new { peerUserId = "@peer:example.org", flowId = "flow-123" });

        Assert.Equal("sas_ready", response.GetProperty("state").GetString());
        Assert.Equal(7, response.GetProperty("emojis").GetArrayLength());
        Assert.Equal(3, response.GetProperty("decimals").GetArrayLength());
    }

    [Fact]
    public async Task PeerVerificationRejectsUntrustedSdkStatusAndIncompleteSas()
    {
        var payload = JsonSerializer.SerializeToElement(new
        {
            peerUserId = "@peer:example.org",
            flowId = "flow-123",
            state = "sas_ready",
            emojis = new[] { new { symbol = "🐶", description = "Dog" } },
            decimals = Array.Empty<int>(),
            identityStatus = "trusted",
        });
        var transport = PeerVerificationTransport(payload);
        await using var service = new WorkerProcessService(Options(), new ScriptedLauncher(() => transport));

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() => service.SendCommandAsync(
            WorkerMethod.PeerVerificationStatus,
            new { peerUserId = "@peer:example.org", flowId = "flow-123" }));

        Assert.Equal(WorkerServiceFailure.MalformedResponse, error.Failure);
        Assert.True(transport.IsDisposed);
    }

    [Fact]
    public async Task InvitationListPreservesEncryptionAndDirectnessFlagsForUiGating()
    {
        var transport = new ScriptedTransport(request => request.Method == WorkerMethod.Hello
            ? Reply(request)
            : WorkerProtocol.SerializeResponseFrame(new WorkerResponse(
                request.Id,
                WorkerResponseKind.Generic,
                null,
                ResultPayload: JsonSerializer.SerializeToElement(new
                {
                    invites = new[]
                    {
                        new { roomId = "!secure:example.org", isDirect = true, encrypted = true, encryptionKnown = true },
                        new { roomId = "!unknown:example.org", isDirect = true, encrypted = false, encryptionKnown = false },
                    },
                }))));
        await using var service = new WorkerProcessService(Options(), new ScriptedLauncher(() => transport));

        var result = await service.SendCommandAsync(WorkerMethod.InvitesList, new { });

        Assert.Equal(2, result.GetProperty("invites").GetArrayLength());
        Assert.True(result.GetProperty("invites")[0].GetProperty("isDirect").GetBoolean());
        Assert.True(result.GetProperty("invites")[0].GetProperty("encrypted").GetBoolean());
        Assert.False(result.GetProperty("invites")[1].GetProperty("encryptionKnown").GetBoolean());
    }

    [Fact]
    public async Task InviteAcceptanceResponseMustConfirmEncryption()
    {
        var transport = new ScriptedTransport(request => request.Method == WorkerMethod.Hello
            ? Reply(request)
            : WorkerProtocol.SerializeResponseFrame(new WorkerResponse(
                request.Id,
                WorkerResponseKind.Generic,
                null,
                ResultPayload: JsonSerializer.SerializeToElement(new
                {
                    roomId = "!room:example.org",
                    encrypted = false,
                    encryptionKnown = true,
                }))));
        await using var service = new WorkerProcessService(Options(), new ScriptedLauncher(() => transport));

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() =>
            service.SendCommandAsync(WorkerMethod.RoomAcceptInvite, new { roomId = "!room:example.org" }));

        Assert.Equal(WorkerServiceFailure.MalformedResponse, error.Failure);
        Assert.True(transport.IsDisposed);
    }

    [Fact]
    public async Task MessageHistoryCannotBeAcceptedUnlessRoomEncryptionIsTrue()
    {
        var transport = new ScriptedTransport(request => request.Method == WorkerMethod.Hello
            ? Reply(request)
            : WorkerProtocol.SerializeResponseFrame(new WorkerResponse(
                request.Id,
                WorkerResponseKind.Generic,
                null,
                ResultPayload: JsonSerializer.SerializeToElement(new
                {
                    roomId = "!room:example.org",
                    encrypted = false,
                    events = Array.Empty<object>(),
                }))));
        await using var service = new WorkerProcessService(Options(), new ScriptedLauncher(() => transport));

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() =>
            service.SendCommandAsync(WorkerMethod.RoomMessages, new { roomId = "!room:example.org" }));

        Assert.Equal(WorkerServiceFailure.MalformedResponse, error.Failure);
        Assert.True(transport.IsDisposed);
    }

    [Fact]
    public async Task WorkerExitFailsPendingStatusAndNextRefreshStartsACleanWorker()
    {
        var exitedTransport = new ScriptedTransport(ReplyToEveryRequest, exitAfterHello: true);
        var nextTransport = new ScriptedTransport(ReplyToEveryRequest);
        var launcher = new ScriptedLauncher(() => exitedTransport, () => nextTransport);
        await using var service = new WorkerProcessService(Options(), launcher);

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() => service.GetPrivacyStatusAsync());
        Assert.Equal(WorkerServiceFailure.WorkerExited, error.Failure);
        Assert.True(exitedTransport.IsDisposed);

        var status = await service.GetPrivacyStatusAsync();

        Assert.Equal(new WorkerPrivacyStatus("matrix_sdk_available", "tor_required", "sdk_feature_available", "not_checked"), status);
        Assert.Equal(2, launcher.StartCount);
        Assert.True(nextTransport.Requests.SequenceEqual([WorkerMethod.Hello, WorkerMethod.PrivacyStatus]));
        Assert.Equal(WorkerConnectionState.Connected, service.ConnectionState);
    }

    [Fact]
    public async Task WorkerExitWhileARequestIsPendingFailsAndDisposesTheTransport()
    {
        var transport = new ScriptedTransport(request =>
            request.Method == WorkerMethod.Hello ? Reply(request) : null);
        var launcher = new ScriptedLauncher(() => transport);
        await using var service = new WorkerProcessService(Options(TimeSpan.FromSeconds(5)), launcher);
        var request = service.GetPrivacyStatusAsync();
        await transport.WaitForRequestAsync(WorkerMethod.PrivacyStatus, TimeSpan.FromSeconds(2));

        transport.Terminate();
        var error = await Assert.ThrowsAsync<WorkerServiceException>(() => request);

        Assert.Equal(WorkerServiceFailure.WorkerExited, error.Failure);
        Assert.True(transport.IsDisposed);
        Assert.Equal(WorkerConnectionState.Faulted, service.ConnectionState);
    }

    [Fact]
    public async Task DisposalCancelsPendingRequestAndCleansUpTheWorker()
    {
        var transport = new ScriptedTransport(request =>
            request.Method == WorkerMethod.Hello ? Reply(request) : null);
        var launcher = new ScriptedLauncher(() => transport);
        var service = new WorkerProcessService(Options(TimeSpan.FromSeconds(10)), launcher);
        var pendingRequest = service.GetPrivacyStatusAsync();
        await transport.WaitForRequestAsync(WorkerMethod.PrivacyStatus, TimeSpan.FromSeconds(2));

        await service.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => pendingRequest);
        await service.DisposeAsync();

        Assert.True(transport.IsDisposed);
        Assert.Equal(WorkerConnectionState.Disposed, service.ConnectionState);
    }

    [Fact]
    public async Task DisposalBeforeStartIsIdempotentAndPreventsLaterLaunch()
    {
        var launcher = new ScriptedLauncher(() => new ScriptedTransport(ReplyToEveryRequest));
        var service = new WorkerProcessService(Options(), launcher);

        await service.DisposeAsync();
        await service.DisposeAsync();

        Assert.Equal(WorkerConnectionState.Disposed, service.ConnectionState);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => service.GetPrivacyStatusAsync());
        Assert.Equal(0, launcher.StartCount);
    }

    [Fact]
    public async Task StartupFailureIsReportedWithoutLeakingAnExceptionMessage()
    {
        var service = new WorkerProcessService(Options(), new FailingLauncher());
        await using (service)
        {
            var error = await Assert.ThrowsAsync<WorkerServiceException>(() => service.GetPrivacyStatusAsync());

            Assert.Equal(WorkerServiceFailure.StartupFailed, error.Failure);
            Assert.DoesNotContain("private path", error.Message, StringComparison.Ordinal);
            Assert.Equal(WorkerConnectionState.Faulted, service.ConnectionState);
        }
    }

    private static WorkerProcessOptions Options(TimeSpan? timeout = null) =>
        new(Path.Combine(Path.GetTempPath(), "veil-chat-fake-worker"), requestTimeout: timeout);

    private static byte[] ReplyToEveryRequest(WorkerRequest request) => Reply(request);

    private static byte[] Reply(WorkerRequest request) =>
        WorkerProtocol.SerializeResponseFrame(WorkerProtocol.Dispatch(request));

    private static ScriptedTransport PeerVerificationTransport(JsonElement payload) =>
        new(request => request.Method == WorkerMethod.Hello
            ? Reply(request)
            : WorkerProtocol.SerializeResponseFrame(new WorkerResponse(
                request.Id,
                WorkerResponseKind.Generic,
                null,
                ResultPayload: payload)));

    private sealed class ScriptedLauncher(params Func<ScriptedTransport>[] factories) : IWorkerProcessLauncher
    {
        private int _startCount;

        public int StartCount => Volatile.Read(ref _startCount);

        public IWorkerProcessTransport Start(WorkerProcessOptions options)
        {
            var index = Interlocked.Increment(ref _startCount) - 1;
            if (index >= factories.Length)
            {
                throw new InvalidOperationException("No scripted transport remains.");
            }

            return factories[index]();
        }
    }

    private sealed class FailingLauncher : IWorkerProcessLauncher
    {
        public IWorkerProcessTransport Start(WorkerProcessOptions options) =>
            throw new InvalidOperationException("private path and process details");
    }

    private sealed class ScriptedTransport : IWorkerProcessTransport
    {
        private readonly ChannelReadStream _output = new();
        private readonly Func<WorkerRequest, CancellationToken, ValueTask<byte[]?>> _response;
        private readonly bool _exitAfterHello;
        private readonly ConcurrentDictionary<WorkerMethod, TaskCompletionSource<bool>> _requestSignals = new();
        private int _hasExited;
        private int _disposed;

        public Stream StandardInput { get; }

        public Stream StandardOutput => _output;

        public bool HasExited => Volatile.Read(ref _hasExited) != 0;

        public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

        public List<WorkerMethod> Requests { get; } = [];

        public List<Guid> RequestIds { get; } = [];

        public ScriptedTransport(Func<WorkerRequest, byte[]?> response, bool exitAfterHello = false)
            : this((request, _) => ValueTask.FromResult(response(request)), exitAfterHello)
        {
        }

        public ScriptedTransport(
            Func<WorkerRequest, CancellationToken, ValueTask<byte[]?>> response,
            bool exitAfterHello = false)
        {
            _response = response;
            _exitAfterHello = exitAfterHello;
            StandardInput = new RequestWriteStream(HandleRequestAsync);
        }

        public async Task WaitForRequestAsync(WorkerMethod method, TimeSpan timeout)
        {
            using var cancellation = new CancellationTokenSource(timeout);
            var signal = _requestSignals.GetOrAdd(method, _ => new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously));
            await signal.Task.WaitAsync(cancellation.Token);
        }

        private async ValueTask HandleRequestAsync(byte[] frame, CancellationToken cancellationToken)
        {
            var parsed = WorkerProtocol.ParseRequest(frame);
            if (!parsed.IsSuccess || parsed.Request is null)
            {
                Exit();
                return;
            }

            var request = parsed.Request;
            lock (Requests)
            {
                Requests.Add(request.Method);
                RequestIds.Add(request.Id);
            }

            _requestSignals.GetOrAdd(request.Method, _ => new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously))
                .TrySetResult(true);
            var reply = await _response(request, cancellationToken);
            if (reply is not null)
            {
                await _output.EnqueueAsync(reply, cancellationToken);
            }

            if (_exitAfterHello && request.Method == WorkerMethod.Hello)
            {
                Exit();
            }
        }

        private void Exit()
        {
            if (Interlocked.Exchange(ref _hasExited, 1) == 0)
            {
                _output.Complete();
            }
        }

        public void Terminate() => Exit();

        public ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _disposed, 1);
            Exit();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RequestWriteStream(Func<byte[], CancellationToken, ValueTask> onFrame) : Stream
    {
        private readonly MemoryStream _pending = new();

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            foreach (var current in buffer.ToArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (current == (byte)'\n')
                {
                    var frame = _pending.ToArray();
                    _pending.SetLength(0);
                    await onFrame(frame, cancellationToken);
                }
                else
                {
                    _pending.WriteByte(current);
                }
            }
        }
    }

    private sealed class ChannelReadStream : Stream
    {
        private readonly Channel<byte[]> _channel = Channel.CreateUnbounded<byte[]>();
        private byte[]? _current;
        private int _offset;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public ValueTask EnqueueAsync(byte[] frame, CancellationToken cancellationToken) =>
            _channel.Writer.WriteAsync(frame, cancellationToken);

        public void Complete() => _channel.Writer.TryComplete();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.IsEmpty)
            {
                return 0;
            }

            while (_current is null || _offset == _current.Length)
            {
                if (!await _channel.Reader.WaitToReadAsync(cancellationToken))
                {
                    return 0;
                }

                if (_channel.Reader.TryRead(out _current))
                {
                    _offset = 0;
                }
            }

            var count = Math.Min(buffer.Length, _current.Length - _offset);
            _current.AsMemory(_offset, count).CopyTo(buffer);
            _offset += count;
            return count;
        }
    }
}
