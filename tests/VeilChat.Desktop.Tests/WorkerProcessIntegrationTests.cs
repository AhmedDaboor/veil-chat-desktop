using System.Diagnostics;
using System.Text;
using System.Text.Json;
using VeilChat.Desktop.Core.Ipc;
using VeilChat.Desktop.Core.Services;
using Xunit;

namespace VeilChat.Desktop.Tests;

/// <summary>
/// These tests launch the real offline Rust worker. On Windows, a Linux worker
/// built by the documented WSL command is started through wsl.exe --exec with
/// an explicit executable path; no command shell or shell script is involved.
/// </summary>
public sealed class WorkerProcessIntegrationTests
{
    private const int MaxFrameBytes = 64 * 1024;
    private static readonly TimeSpan IoTimeout = TimeSpan.FromSeconds(10);
    private static readonly Guid FirstId = Guid.Parse("d41c435b-24c8-458a-b873-3ca1d77c2c34");
    private static readonly Guid SecondId = Guid.Parse("d59a7451-0d8c-482c-9a84-5160193226da");

    [Fact]
    public async Task RealWorkerHandlesHelloAndPrivacyStatusWithCorrelatedResponses()
    {
        await using var worker = StartWorker();

        await worker.WriteLineAsync(Request(FirstId, "worker.hello"));
        await worker.WriteLineAsync(Request(SecondId, "privacy.status"));

        using var hello = JsonDocument.Parse(await worker.ReadLineAsync());
        Assert.Equal(WorkerProtocol.CurrentVersion, hello.RootElement.GetProperty("v").GetInt32());
        Assert.Equal("response", hello.RootElement.GetProperty("kind").GetString());
        Assert.Equal(FirstId.ToString("D"), hello.RootElement.GetProperty("id").GetString());
        Assert.True(hello.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal(WorkerProtocol.CurrentVersion, hello.RootElement.GetProperty("result").GetProperty("protocolVersion").GetInt32());

        using var privacy = JsonDocument.Parse(await worker.ReadLineAsync());
        Assert.Equal(SecondId.ToString("D"), privacy.RootElement.GetProperty("id").GetString());
        Assert.True(privacy.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("matrix_sdk_available", privacy.RootElement.GetProperty("result").GetProperty("state").GetString());
        Assert.Equal("tor_required", privacy.RootElement.GetProperty("result").GetProperty("networkAccess").GetString());

        worker.CloseInput();
        Assert.Equal(0, await worker.WaitForExitAsync());
        Assert.Empty(await worker.ReadStandardErrorAsync());
    }

    [Fact]
    public async Task WorkerStatusServiceUsesTheCompiledRustWorker()
    {
        await using var service = new WorkerProcessService(CreateRealWorkerOptions(), new ProcessWorkerLauncher());

        var status = await service.GetPrivacyStatusAsync();

        Assert.Equal(new WorkerPrivacyStatus("matrix_sdk_available", "tor_required", "sdk_feature_available", "not_checked"), status);
        Assert.Equal(WorkerConnectionState.Connected, service.ConnectionState);
    }

    [Fact]
    public async Task MatrixLoginFailsClosedWhenNoTorExecutableIsConfigured()
    {
        await using var service = new WorkerProcessService(CreateRealWorkerOptions(), new ProcessWorkerLauncher());

        var error = await Assert.ThrowsAsync<WorkerServiceException>(() => service.SendCommandAsync(
            WorkerMethod.MatrixLogin,
            new
            {
                homeserver = "https://example.org",
                username = "alice",
                password = "NEVER_ECHO_OR_LOG_THIS",
                storePassphrase = "random-session-store-passphrase",
                storeId = "a34585cf-3381-4fdd-a122-945360e3878c",
            }));

        Assert.Equal(WorkerServiceFailure.RemoteError, error.Failure);
        Assert.Equal(WorkerErrorCode.TorNotConfigured, error.ErrorCode);
        Assert.Equal(WorkerConnectionState.Connected, service.ConnectionState);
        var torStatus = await service.GetTorStatusAsync();
        Assert.Equal(new WorkerTorStatus("not_configured", false), torStatus);
    }

    [Fact]
    public async Task EveryMatrixNetworkOperationFailsClosedWhenNoTorExecutableIsConfigured()
    {
        await using var service = new WorkerProcessService(CreateRealWorkerOptions(), new ProcessWorkerLauncher());
        var networkOperations = new (WorkerMethod Method, object Payload)[]
        {
            (WorkerMethod.MatrixLogin, new
            {
                homeserver = "https://example.org",
                username = "alice",
                password = "test-password",
                storePassphrase = new string('a', 64),
                storeId = "a34585cf-3381-4fdd-a122-945360e3878c",
            }),
            (WorkerMethod.MatrixRestore, new
            {
                homeserver = "https://example.org",
                session = new { access_token = "test-token", device_id = "TESTDEVICE", user_id = "@alice:example.org" },
                storePassphrase = new string('b', 64),
                storeId = "b34585cf-3381-4fdd-a122-945360e3878c",
            }),
            (WorkerMethod.MatrixLogout, new { }),
            (WorkerMethod.RoomsList, new { }),
            (WorkerMethod.InvitesList, new { }),
            (WorkerMethod.RoomCreateDirect, new { userId = "@bob:example.org" }),
            (WorkerMethod.RoomAcceptInvite, new { roomId = "!room:example.org" }),
            (WorkerMethod.RoomMessages, new { roomId = "!room:example.org" }),
            (WorkerMethod.RoomSendText, new { roomId = "!room:example.org", body = "test message" }),
            (WorkerMethod.PeerVerificationStart, new { peerUserId = "@bob:example.org" }),
            (WorkerMethod.PeerVerificationStatus, new { peerUserId = "@bob:example.org", flowId = "flow-1" }),
            (WorkerMethod.PeerVerificationConfirm, new { peerUserId = "@bob:example.org", flowId = "flow-1" }),
            (WorkerMethod.PeerVerificationCancel, new { peerUserId = "@bob:example.org", flowId = "flow-1" }),
        };

        foreach (var (method, payload) in networkOperations)
        {
            var error = await Assert.ThrowsAsync<WorkerServiceException>(() =>
                service.SendCommandAsync(method, payload));

            Assert.Equal(WorkerServiceFailure.RemoteError, error.Failure);
            Assert.Equal(WorkerErrorCode.TorNotConfigured, error.ErrorCode);
            Assert.Equal(WorkerConnectionState.Connected, service.ConnectionState);
        }

        Assert.Equal(new WorkerTorStatus("not_configured", false), await service.GetTorStatusAsync());
    }

    [Fact]
    public async Task RealWorkerRejectsMalformedJsonWithoutEchoingInputAndContinues()
    {
        const string marker = "DO_NOT_ECHO_IPC_PAYLOAD";
        await using var worker = StartWorker();

        await worker.WriteLineAsync($"{{\"payload\":\"{marker}");
        await worker.WriteLineAsync(Request(FirstId, "worker.hello"));

        using var malformed = JsonDocument.Parse(await worker.ReadLineAsync());
        Assert.False(malformed.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("MALFORMED_REQUEST", malformed.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal(JsonValueKind.Null, malformed.RootElement.GetProperty("id").ValueKind);

        using var hello = JsonDocument.Parse(await worker.ReadLineAsync());
        Assert.Equal(FirstId.ToString("D"), hello.RootElement.GetProperty("id").GetString());

        worker.CloseInput();
        Assert.Equal(0, await worker.WaitForExitAsync());
        Assert.DoesNotContain(marker, await worker.ReadStandardErrorAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RealWorkerRejectsUnsupportedProtocolVersionAndPreservesRequestId()
    {
        await using var worker = StartWorker();
        var request = Request(FirstId, "worker.hello", version: 3);

        await worker.WriteLineAsync(request);
        using var response = JsonDocument.Parse(await worker.ReadLineAsync());

        Assert.Equal(FirstId.ToString("D"), response.RootElement.GetProperty("id").GetString());
        Assert.False(response.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("UNSUPPORTED_VERSION", response.RootElement.GetProperty("error").GetProperty("code").GetString());

        worker.CloseInput();
        Assert.Equal(0, await worker.WaitForExitAsync());
    }

    [Fact]
    public async Task RealWorkerReportsOversizedFrameThenExits()
    {
        await using var worker = StartWorker();

        await worker.WriteRawAsync(new string('x', MaxFrameBytes + 1) + "\n");
        worker.CloseInput();
        using var response = JsonDocument.Parse(await worker.ReadLineAsync());

        Assert.False(response.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("FRAME_TOO_LARGE", response.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal(65, await worker.WaitForExitAsync());
        Assert.Contains("FRAME_TOO_LARGE", await worker.ReadStandardErrorAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RealWorkerReportsTruncatedFrameThenExits()
    {
        await using var worker = StartWorker();

        await worker.WriteRawAsync("{\"v\":1,\"kind\":\"request\"");
        worker.CloseInput();
        using var response = JsonDocument.Parse(await worker.ReadLineAsync());

        Assert.False(response.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("TRUNCATED_FRAME", response.RootElement.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal(65, await worker.WaitForExitAsync());
    }

    [Fact]
    public async Task RealWorkerTreatsEmptyEofAsCleanShutdown()
    {
        await using var worker = StartWorker();
        worker.CloseInput();

        Assert.Null(await worker.TryReadLineAsync());
        Assert.Equal(0, await worker.WaitForExitAsync());
    }

    [Fact]
    public async Task TestHostCanCancelAReadAndThenCleanUpTheIdleWorker()
    {
        await using var worker = StartWorker();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await worker.TryReadLineAsync(cancellation.Token));

        worker.CloseInput();
        Assert.Equal(0, await worker.WaitForExitAsync());
    }

    [Fact]
    public async Task TestHostEnforcesIoAndProcessTimeoutsAndCleansUpWorker()
    {
        await using var worker = StartWorker();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await worker.TryReadLineAsync(timeoutOverride: TimeSpan.FromMilliseconds(150)));

        await Assert.ThrowsAsync<Xunit.Sdk.XunitException>(async () =>
        {
            await worker.WaitForExitAsync(timeoutOverride: TimeSpan.FromMilliseconds(150));
        });

        Assert.True(await worker.WaitUntilExitedAsync());
    }

    [Fact]
    public async Task TestHostObservesAndCleansUpAnAbruptWorkerTermination()
    {
        await using var worker = StartWorker();

        worker.Terminate();
        Assert.True(await worker.WaitUntilExitedAsync());
    }

    private static string Request(Guid id, string method, int version = WorkerProtocol.CurrentVersion) =>
        $"{{\"v\":{version},\"kind\":\"request\",\"id\":\"{id:D}\",\"method\":\"{method}\",\"payload\":{{}}}}";

    private static TestWorker StartWorker()
    {
        var desktopRoot = FindDesktopRoot();
        var windowsExecutable = Path.Combine(desktopRoot, "rust-worker", "target", "debug", "veil-chat-ipc-worker.exe");
        var linuxExecutable = Path.Combine(desktopRoot, "rust-worker", "target", "debug", "veil-chat-ipc-worker");
        var startInfo = new ProcessStartInfo
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        if (OperatingSystem.IsWindows() && File.Exists(windowsExecutable))
        {
            startInfo.FileName = windowsExecutable;
        }
        else if (OperatingSystem.IsWindows() && File.Exists(linuxExecutable))
        {
            var distro = Environment.GetEnvironmentVariable("VEIL_CHAT_WORKER_WSL_DISTRO") ?? "Ubuntu-24.04";
            startInfo.FileName = Path.Combine(Environment.SystemDirectory, "wsl.exe");
            startInfo.ArgumentList.Add("--distribution");
            startInfo.ArgumentList.Add(distro);
            startInfo.ArgumentList.Add("--exec");
            startInfo.ArgumentList.Add(ToWslPath(linuxExecutable));
        }
        else if (OperatingSystem.IsLinux() && File.Exists(linuxExecutable))
        {
            startInfo.FileName = linuxExecutable;
        }
        else
        {
            throw new Xunit.Sdk.XunitException(
                $"The compiled Rust worker is required for integration tests. Expected: {windowsExecutable} or {linuxExecutable}");
        }

        var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        if (!process.Start())
        {
            process.Dispose();
            throw new Xunit.Sdk.XunitException("The Rust worker process could not be started.");
        }

        return new TestWorker(process);
    }

    private static WorkerProcessOptions CreateRealWorkerOptions()
    {
        var desktopRoot = FindDesktopRoot();
        var windowsExecutable = Path.Combine(desktopRoot, "rust-worker", "target", "debug", "veil-chat-ipc-worker.exe");
        var linuxExecutable = Path.Combine(desktopRoot, "rust-worker", "target", "debug", "veil-chat-ipc-worker");
        if (OperatingSystem.IsWindows() && File.Exists(windowsExecutable))
        {
            return new WorkerProcessOptions(windowsExecutable);
        }

        if (OperatingSystem.IsWindows() && File.Exists(linuxExecutable))
        {
            var distribution = Environment.GetEnvironmentVariable("VEIL_CHAT_WORKER_WSL_DISTRO") ?? "Ubuntu-24.04";
            return new WorkerProcessOptions(
                Path.Combine(Environment.SystemDirectory, "wsl.exe"),
                ["--distribution", distribution, "--exec", ToWslPath(linuxExecutable)]);
        }

        if (OperatingSystem.IsLinux() && File.Exists(linuxExecutable))
        {
            return new WorkerProcessOptions(linuxExecutable);
        }

        throw new Xunit.Sdk.XunitException(
            $"The compiled Rust worker is required for the service integration test. Expected: {windowsExecutable} or {linuxExecutable}");
    }

    private static string FindDesktopRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "VeilChat.Desktop.sln")))
            {
                return directory.FullName;
            }
        }

        throw new Xunit.Sdk.XunitException("Could not locate VeilChat.Desktop.sln from the test output directory.");
    }

    private static string ToWslPath(string windowsPath)
    {
        var fullPath = Path.GetFullPath(windowsPath);
        if (fullPath.Length < 3 || fullPath[1] != ':' || !Path.IsPathRooted(fullPath))
        {
            throw new Xunit.Sdk.XunitException("The WSL worker must be on a local drive with a /mnt/<drive> mount.");
        }

        return $"/mnt/{char.ToLowerInvariant(fullPath[0])}/{fullPath[3..].Replace('\\', '/')}";
    }

    private sealed class TestWorker : IAsyncDisposable
    {
        private readonly Process _process;

        public TestWorker(Process process) => _process = process;

        public async Task WriteLineAsync(string text) => await WriteRawAsync(text + "\n");

        public async Task WriteRawAsync(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            using var timeout = new CancellationTokenSource(IoTimeout);
            await _process.StandardInput.BaseStream.WriteAsync(bytes, timeout.Token);
            await _process.StandardInput.BaseStream.FlushAsync(timeout.Token);
        }

        public void CloseInput() => _process.StandardInput.Close();

        public async Task<string> ReadLineAsync(CancellationToken cancellationToken = default) =>
            await TryReadLineAsync(cancellationToken)
            ?? throw new Xunit.Sdk.XunitException("The Rust worker closed stdout before returning a protocol frame.");

        public async Task<string?> TryReadLineAsync(
            CancellationToken cancellationToken = default,
            TimeSpan? timeoutOverride = null)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(timeoutOverride ?? IoTimeout);
            using var frame = new MemoryStream(capacity: 512);
            var buffer = new byte[1];

            while (true)
            {
                var count = await _process.StandardOutput.BaseStream.ReadAsync(buffer, timeout.Token);
                if (count == 0)
                {
                    if (frame.Length == 0)
                    {
                        return null;
                    }

                    throw new Xunit.Sdk.XunitException("The Rust worker closed stdout in the middle of a frame.");
                }

                if (buffer[0] == (byte)'\n')
                {
                    return new UTF8Encoding(false, true).GetString(frame.ToArray());
                }

                if (frame.Length == MaxFrameBytes)
                {
                    throw new Xunit.Sdk.XunitException("The Rust worker exceeded the response frame byte limit.");
                }

                frame.WriteByte(buffer[0]);
            }
        }

        public async Task<int> WaitForExitAsync(TimeSpan? timeoutOverride = null)
        {
            using var timeout = new CancellationTokenSource(timeoutOverride ?? IoTimeout);
            try
            {
                await _process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                Terminate();
                throw new Xunit.Sdk.XunitException("The Rust worker did not exit within the integration-test timeout.");
            }

            return _process.ExitCode;
        }

        public async Task<bool> WaitUntilExitedAsync()
        {
            using var timeout = new CancellationTokenSource(IoTimeout);
            try
            {
                await _process.WaitForExitAsync(timeout.Token);
                return true;
            }
            catch (OperationCanceledException)
            {
                Terminate();
                return false;
            }
        }

        public async Task<string> ReadStandardErrorAsync()
        {
            using var timeout = new CancellationTokenSource(IoTimeout);
            return await _process.StandardError.ReadToEndAsync(timeout.Token);
        }

        public void Terminate()
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (!_process.HasExited)
            {
                try
                {
                    _process.StandardInput.Close();
                }
                catch (InvalidOperationException)
                {
                    // The worker may already have closed its input pipe.
                }

                using var grace = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                try
                {
                    await _process.WaitForExitAsync(grace.Token);
                }
                catch (OperationCanceledException)
                {
                    Terminate();
                    using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    try
                    {
                        await _process.WaitForExitAsync(cleanup.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        // The OS may retain a WSL child briefly after its launcher exits.
                    }
                }
            }

            _process.Dispose();
        }
    }
}
