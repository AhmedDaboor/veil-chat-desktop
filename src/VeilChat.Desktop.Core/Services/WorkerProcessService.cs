using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using VeilChat.Desktop.Core.Ipc;

namespace VeilChat.Desktop.Core.Services;

public enum WorkerConnectionState
{
    NotConfigured,
    Stopped,
    Connected,
    Faulted,
    Disposed,
}

public enum WorkerServiceFailure
{
    NotConfigured,
    StartupFailed,
    WorkerExited,
    MalformedResponse,
    RequestTimeout,
    RemoteError,
}

public sealed class WorkerServiceException(WorkerServiceFailure failure, WorkerErrorCode? errorCode = null)
    : IOException("The local worker request could not be completed.")
{
    public WorkerServiceFailure Failure { get; } = failure;

    public WorkerErrorCode? ErrorCode { get; } = errorCode;
}

public sealed record WorkerPrivacyStatus(string State, string NetworkAccess, string E2eeState, string TorState);

public sealed record WorkerTorStatus(string State, bool NetworkOperationsAllowed);

public interface IWorkerStatusService
{
    WorkerConnectionState ConnectionState { get; }

    Task<WorkerPrivacyStatus> GetPrivacyStatusAsync(CancellationToken cancellationToken = default);

    Task<WorkerTorStatus> GetTorStatusAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Worker launch configuration. The application does not search for binaries;
/// callers must provide an absolute executable path explicitly.
/// </summary>
public sealed class WorkerProcessOptions
{
    public string? ExecutablePath { get; }

    public IReadOnlyList<string> Arguments { get; }

    public IReadOnlyDictionary<string, string> EnvironmentVariables { get; }

    public TimeSpan RequestTimeout { get; }

    public TimeSpan ShutdownTimeout { get; }

    public string? ConfigurationIssue { get; }

    public bool IsConfigured => ConfigurationIssue is null && !string.IsNullOrWhiteSpace(ExecutablePath);

    public WorkerProcessOptions(
        string? executablePath,
        IEnumerable<string>? arguments = null,
        TimeSpan? requestTimeout = null,
        TimeSpan? shutdownTimeout = null,
        string? configurationIssue = null,
        IReadOnlyDictionary<string, string>? environmentVariables = null)
    {
        ExecutablePath = executablePath;
        Arguments = Array.AsReadOnly((arguments ?? []).ToArray());
        EnvironmentVariables = new Dictionary<string, string>(
            environmentVariables ?? new Dictionary<string, string>(),
            OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        RequestTimeout = requestTimeout ?? TimeSpan.FromSeconds(5);
        ShutdownTimeout = shutdownTimeout ?? TimeSpan.FromSeconds(2);
        ConfigurationIssue = configurationIssue;

        if (RequestTimeout <= TimeSpan.Zero || ShutdownTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(requestTimeout), "Worker timeouts must be positive.");
        }
    }

    public static WorkerProcessOptions FromEnvironment()
    {
        var dataDirectory = Environment.GetEnvironmentVariable("VEIL_CHAT_DATA_DIRECTORY");
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            dataDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VeilChat");
        }

        var executable = Environment.GetEnvironmentVariable("VEIL_CHAT_WORKER_EXECUTABLE");
        if (!string.IsNullOrWhiteSpace(executable))
        {
            if (!Path.IsPathFullyQualified(executable))
            {
                return Unconfigured("VEIL_CHAT_WORKER_EXECUTABLE must be an absolute path.");
            }

            if (!Path.IsPathFullyQualified(dataDirectory))
            {
                return Unconfigured("VEIL_CHAT_DATA_DIRECTORY must be an absolute path.");
            }

            var childEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["VEIL_CHAT_DATA_DIRECTORY"] = dataDirectory,
            };
            AddConfiguredTorExecutable(childEnvironment, "VEIL_CHAT_TOR_EXECUTABLE");
            return new WorkerProcessOptions(executable, environmentVariables: childEnvironment);
        }

        if (OperatingSystem.IsWindows())
        {
            var linuxExecutable = Environment.GetEnvironmentVariable("VEIL_CHAT_WORKER_LINUX_EXECUTABLE");
            var distribution = Environment.GetEnvironmentVariable("VEIL_CHAT_WORKER_WSL_DISTRO");
            if (!string.IsNullOrWhiteSpace(linuxExecutable) || !string.IsNullOrWhiteSpace(distribution))
            {
                if (string.IsNullOrWhiteSpace(linuxExecutable) ||
                    !linuxExecutable.StartsWith("/", StringComparison.Ordinal) ||
                    string.IsNullOrWhiteSpace(distribution))
                {
                    return Unconfigured(
                        "Set both VEIL_CHAT_WORKER_LINUX_EXECUTABLE and VEIL_CHAT_WORKER_WSL_DISTRO to configure WSL.");
                }

                var wslExecutable = Path.Combine(Environment.SystemDirectory, "wsl.exe");
                var linuxDataDirectory = Environment.GetEnvironmentVariable("VEIL_CHAT_LINUX_DATA_DIRECTORY");
                var linuxTorExecutable = Environment.GetEnvironmentVariable("VEIL_CHAT_TOR_LINUX_EXECUTABLE");
                if (string.IsNullOrWhiteSpace(linuxDataDirectory) || !linuxDataDirectory.StartsWith("/", StringComparison.Ordinal))
                {
                    return Unconfigured("Set VEIL_CHAT_LINUX_DATA_DIRECTORY to an absolute WSL data directory.");
                }
                if (string.IsNullOrWhiteSpace(linuxTorExecutable) || !linuxTorExecutable.StartsWith("/", StringComparison.Ordinal))
                {
                    return Unconfigured("Set VEIL_CHAT_TOR_LINUX_EXECUTABLE to an absolute WSL Tor executable path.");
                }

                return new WorkerProcessOptions(
                    wslExecutable,
                    ["--distribution", distribution, "--exec", "/usr/bin/env",
                        $"VEIL_CHAT_DATA_DIRECTORY={linuxDataDirectory}",
                        $"VEIL_CHAT_TOR_EXECUTABLE={linuxTorExecutable}", linuxExecutable],
                    environmentVariables: new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["VEIL_CHAT_DATA_DIRECTORY"] = linuxDataDirectory,
                        ["VEIL_CHAT_TOR_EXECUTABLE"] = linuxTorExecutable,
                    });
            }
        }

        return Unconfigured("Set VEIL_CHAT_WORKER_EXECUTABLE to an absolute worker path.");
    }

    public static WorkerProcessOptions Unconfigured(string issue) =>
        new(null, configurationIssue: issue);

    private static void AddConfiguredTorExecutable(IDictionary<string, string> childEnvironment, string variableName)
    {
        var torExecutable = Environment.GetEnvironmentVariable(variableName);
        if (!string.IsNullOrWhiteSpace(torExecutable) && Path.IsPathFullyQualified(torExecutable) && File.Exists(torExecutable))
        {
            childEnvironment["VEIL_CHAT_TOR_EXECUTABLE"] = torExecutable;
        }
    }
}

public interface IWorkerProcessTransport : IAsyncDisposable
{
    Stream StandardInput { get; }

    Stream StandardOutput { get; }

    bool HasExited { get; }
}

public interface IWorkerProcessLauncher
{
    IWorkerProcessTransport Start(WorkerProcessOptions options);
}

/// <summary>
/// Owns one worker connection and serializes the protocol's request/response
/// exchange. The v2 worker is intentionally limited to one in-flight request.
/// </summary>
public sealed class WorkerProcessService : IWorkerStatusService, IAsyncDisposable, IDisposable
{
    private readonly WorkerProcessOptions _options;
    private readonly IWorkerProcessLauncher _launcher;
    private readonly SemaphoreSlim _requestGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _disposeLock = new();
    private IWorkerProcessTransport? _transport;
    private WorkerFrameReader? _frameReader;
    private Task? _disposeTask;
    private int _connectionState;
    private int _disposeRequested;

    public WorkerConnectionState ConnectionState => (WorkerConnectionState)Volatile.Read(ref _connectionState);

    public WorkerProcessService(WorkerProcessOptions options, IWorkerProcessLauncher launcher)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(launcher);
        _options = options;
        _launcher = launcher;
        _connectionState = options.IsConfigured
            ? (int)WorkerConnectionState.Stopped
            : (int)WorkerConnectionState.NotConfigured;
    }

    public async Task<WorkerPrivacyStatus> GetPrivacyStatusAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExchangeCommandAsync(
            WorkerMethod.PrivacyStatus,
            JsonSerializer.SerializeToElement(new { }),
            _options.RequestTimeout,
            cancellationToken).ConfigureAwait(false);
        if (response.Result != WorkerResponseKind.PrivacyStatus || response.ResultPayload is not { } payload ||
            !payload.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.String ||
            !payload.TryGetProperty("networkAccess", out var network) || network.ValueKind != JsonValueKind.String ||
            !payload.TryGetProperty("e2ee", out var e2ee) || e2ee.ValueKind != JsonValueKind.String ||
            !payload.TryGetProperty("tor", out var tor) || tor.ValueKind != JsonValueKind.String)
        {
            throw new WorkerServiceException(WorkerServiceFailure.MalformedResponse);
        }

        return new WorkerPrivacyStatus(state.GetString()!, network.GetString()!, e2ee.GetString()!, tor.GetString()!);
    }

    public async Task<WorkerTorStatus> GetTorStatusAsync(CancellationToken cancellationToken = default)
    {
        var response = await ExchangeCommandAsync(
            WorkerMethod.TorStatus,
            JsonSerializer.SerializeToElement(new { }),
            _options.RequestTimeout,
            cancellationToken).ConfigureAwait(false);
        var payload = response.ResultPayload ?? throw new WorkerServiceException(WorkerServiceFailure.MalformedResponse);
        if (!payload.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.String ||
            !payload.TryGetProperty("networkOperationsAllowed", out var allowed) ||
            allowed.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new WorkerServiceException(WorkerServiceFailure.MalformedResponse);
        }
        return new WorkerTorStatus(state.GetString()!, allowed.GetBoolean());
    }

    /// <summary>Send one typed v2 command over the existing single-flight worker pipe.</summary>
    public async Task<JsonElement> SendCommandAsync(
        WorkerMethod method,
        object payload,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (method is WorkerMethod.Hello or WorkerMethod.PrivacyStatus or WorkerMethod.TorStatus)
        {
            throw new ArgumentOutOfRangeException(nameof(method), "Use the typed status methods for status calls.");
        }

        var serialized = JsonSerializer.SerializeToElement(payload, payload.GetType());
        var response = await ExchangeCommandAsync(method, serialized, timeout ?? _options.RequestTimeout, cancellationToken)
            .ConfigureAwait(false);
        if (response.Result != WorkerResponseKind.Generic || response.ResultPayload is not { } result)
        {
            throw new WorkerServiceException(WorkerServiceFailure.MalformedResponse);
        }
        return result.Clone();
    }

    public async Task StopWorkerAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        await _requestGate.WaitAsync(waitCancellation.Token).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await InvalidateTransportAsync().ConfigureAwait(false);
            SetConnectionState(_options.IsConfigured ? WorkerConnectionState.Stopped : WorkerConnectionState.NotConfigured);
        }
        finally
        {
            _requestGate.Release();
        }
    }

    private async Task<WorkerResponse> ExchangeCommandAsync(
        WorkerMethod method,
        JsonElement payload,
        TimeSpan requestTimeout,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        try
        {
            await _requestGate.WaitAsync(waitCancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            throw new ObjectDisposedException(nameof(WorkerProcessService));
        }

        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            if (!_options.IsConfigured)
            {
                SetConnectionState(WorkerConnectionState.NotConfigured);
                throw new WorkerServiceException(WorkerServiceFailure.NotConfigured);
            }

            if (_transport?.HasExited == true)
            {
                await InvalidateTransportAsync().ConfigureAwait(false);
                SetConnectionState(WorkerConnectionState.Faulted);
                throw new WorkerServiceException(WorkerServiceFailure.WorkerExited);
            }

            if (_transport is null)
            {
                await StartAndHandshakeAsync(cancellationToken).ConfigureAwait(false);
            }

            var response = await ExchangeAsync(new WorkerRequest(Guid.NewGuid(), method, payload), cancellationToken, requestTimeout)
                .ConfigureAwait(false);
            if (!WorkerProtocol.IsExpectedResponsePayload(method, response))
            {
                await FailProtocolAsync().ConfigureAwait(false);
            }
            if (_transport?.HasExited == true)
            {
                await InvalidateTransportAsync().ConfigureAwait(false);
                SetConnectionState(WorkerConnectionState.Faulted);
                throw new WorkerServiceException(WorkerServiceFailure.WorkerExited);
            }
            return response;
        }
        finally
        {
            _requestGate.Release();
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_disposeLock)
        {
            _disposeTask ??= DisposeCoreAsync();
            return new ValueTask(_disposeTask);
        }
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    private async Task StartAndHandshakeAsync(CancellationToken cancellationToken)
    {
        IWorkerProcessTransport transport;
        try
        {
            transport = _launcher.Start(_options);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            SetConnectionState(WorkerConnectionState.Faulted);
            throw new WorkerServiceException(WorkerServiceFailure.StartupFailed);
        }

        _transport = transport;
        _frameReader = new WorkerFrameReader(transport.StandardOutput);
        if (transport.HasExited)
        {
            await InvalidateTransportAsync().ConfigureAwait(false);
            SetConnectionState(WorkerConnectionState.Faulted);
            throw new WorkerServiceException(WorkerServiceFailure.WorkerExited);
        }

        try
        {
            var hello = await ExchangeAsync(
                new WorkerRequest(Guid.NewGuid(), WorkerMethod.Hello),
                cancellationToken,
                _options.RequestTimeout).ConfigureAwait(false);
            if (hello.Result != WorkerResponseKind.Hello || hello.ProtocolVersion != WorkerProtocol.CurrentVersion)
            {
                await FailProtocolAsync().ConfigureAwait(false);
            }

            SetConnectionState(WorkerConnectionState.Connected);
        }
        catch
        {
            await InvalidateTransportAsync().ConfigureAwait(false);
            if (Volatile.Read(ref _disposeRequested) == 0)
            {
                SetConnectionState(WorkerConnectionState.Faulted);
            }

            throw;
        }
    }

    private async Task<WorkerResponse> ExchangeAsync(
        WorkerRequest request,
        CancellationToken cancellationToken,
        TimeSpan requestTimeout)
    {
        var transport = _transport ?? throw new WorkerServiceException(WorkerServiceFailure.WorkerExited);
        var reader = _frameReader ?? throw new WorkerServiceException(WorkerServiceFailure.WorkerExited);
        using var timeout = new CancellationTokenSource(requestTimeout);
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, timeout.Token, _lifetime.Token);

        byte[] responseFrame;
        try
        {
            if (transport.HasExited)
            {
                throw new WorkerServiceException(WorkerServiceFailure.WorkerExited);
            }

            var requestFrame = WorkerProtocol.SerializeRequestFrame(request);
            try
            {
                await transport.StandardInput.WriteAsync(requestFrame.AsMemory(), linkedCancellation.Token).ConfigureAwait(false);
                await transport.StandardInput.FlushAsync(linkedCancellation.Token).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(requestFrame);
            }

            var receivedFrame = await reader.ReadFrameAsync(linkedCancellation.Token).ConfigureAwait(false);
            if (receivedFrame is null)
            {
                throw new WorkerServiceException(WorkerServiceFailure.WorkerExited);
            }

            if (reader.HasBufferedBytes)
            {
                throw new WorkerFrameException(WorkerErrorCode.InvalidRequest);
            }

            responseFrame = receivedFrame;
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            await InvalidateTransportAsync().ConfigureAwait(false);
            throw new ObjectDisposedException(nameof(WorkerProcessService));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await InvalidateTransportAsync().ConfigureAwait(false);
            SetConnectionState(WorkerConnectionState.Faulted);
            throw;
        }
        catch (OperationCanceledException)
        {
            await InvalidateTransportAsync().ConfigureAwait(false);
            SetConnectionState(WorkerConnectionState.Faulted);
            throw new WorkerServiceException(WorkerServiceFailure.RequestTimeout);
        }
        catch (WorkerServiceException)
        {
            await InvalidateTransportAsync().ConfigureAwait(false);
            SetConnectionState(WorkerConnectionState.Faulted);
            throw;
        }
        catch (WorkerFrameException)
        {
            await InvalidateTransportAsync().ConfigureAwait(false);
            SetConnectionState(WorkerConnectionState.Faulted);
            throw new WorkerServiceException(WorkerServiceFailure.MalformedResponse);
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException or InvalidOperationException)
        {
            await InvalidateTransportAsync().ConfigureAwait(false);
            SetConnectionState(WorkerConnectionState.Faulted);
            throw new WorkerServiceException(WorkerServiceFailure.WorkerExited);
        }

        WorkerResponseParseResult parsed;
        try
        {
            parsed = WorkerProtocol.ParseResponse(responseFrame);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(responseFrame);
        }
        if (!parsed.IsSuccess || parsed.Response is null)
        {
            await FailProtocolAsync().ConfigureAwait(false);
        }

        var response = parsed.Response!;
        if (response.RequestId != request.Id)
        {
            await FailProtocolAsync().ConfigureAwait(false);
        }

        if (response.ErrorCode is not null)
        {
            throw new WorkerServiceException(WorkerServiceFailure.RemoteError, response.ErrorCode);
        }

        return response;
    }

    private async Task FailProtocolAsync()
    {
        await InvalidateTransportAsync().ConfigureAwait(false);
        SetConnectionState(WorkerConnectionState.Faulted);
        throw new WorkerServiceException(WorkerServiceFailure.MalformedResponse);
    }

    private async Task InvalidateTransportAsync()
    {
        var transport = _transport;
        _transport = null;
        _frameReader = null;
        if (transport is not null)
        {
            try
            {
                await transport.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                // Process cleanup is best effort; never replace the request's safe failure.
            }
        }
    }

    private async Task DisposeCoreAsync()
    {
        Interlocked.Exchange(ref _disposeRequested, 1);
        _lifetime.Cancel();
        await _requestGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await InvalidateTransportAsync().ConfigureAwait(false);
            SetConnectionState(WorkerConnectionState.Disposed);
        }
        finally
        {
            _requestGate.Release();
            _requestGate.Dispose();
            _lifetime.Dispose();
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposeRequested) != 0)
        {
            throw new ObjectDisposedException(nameof(WorkerProcessService));
        }
    }

    private void SetConnectionState(WorkerConnectionState state) =>
        Volatile.Write(ref _connectionState, (int)state);
}

public sealed class ProcessWorkerLauncher : IWorkerProcessLauncher
{
    public IWorkerProcessTransport Start(WorkerProcessOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.IsConfigured || string.IsNullOrWhiteSpace(options.ExecutablePath))
        {
            throw new InvalidOperationException("Worker executable configuration is missing.");
        }

        if (!Path.IsPathFullyQualified(options.ExecutablePath) || !File.Exists(options.ExecutablePath))
        {
            throw new FileNotFoundException("Configured worker executable is unavailable.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = options.ExecutablePath,
            WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(options.ExecutablePath))!,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.Environment.Clear();
        var inheritedVariables = OperatingSystem.IsWindows()
            ? new[] { "SystemRoot", "WINDIR", "PATH", "TEMP", "TMP" }
            : new[] { "PATH", "TMPDIR" };
        foreach (var variable in inheritedVariables)
        {
            var value = Environment.GetEnvironmentVariable(variable);
            if (!string.IsNullOrEmpty(value))
            {
                startInfo.Environment[variable] = value;
            }
        }
        foreach (var variable in options.EnvironmentVariables)
        {
            startInfo.Environment[variable.Key] = variable.Value;
        }
        foreach (var argument in options.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        try
        {
            if (!process.Start())
            {
                throw new InvalidOperationException("The configured worker process did not start.");
            }

            return new ProcessWorkerTransport(process, options.ShutdownTimeout);
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }
}

internal sealed class ProcessWorkerTransport : IWorkerProcessTransport
{
    private readonly Process _process;
    private readonly TimeSpan _shutdownTimeout;
    private readonly Task _standardErrorDrain;
    private int _disposed;

    public Stream StandardInput => _process.StandardInput.BaseStream;

    public Stream StandardOutput => _process.StandardOutput.BaseStream;

    public bool HasExited
    {
        get
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                return true;
            }

            try
            {
                return _process.HasExited;
            }
            catch (InvalidOperationException)
            {
                return true;
            }
        }
    }

    public ProcessWorkerTransport(Process process, TimeSpan shutdownTimeout)
    {
        _process = process;
        _shutdownTimeout = shutdownTimeout;
        _standardErrorDrain = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            try
            {
                _process.StandardInput.Close();
            }
            catch (InvalidOperationException)
            {
                // The process may already have closed its input pipe.
            }

            try
            {
                using var graceful = new CancellationTokenSource(_shutdownTimeout);
                await _process.WaitForExitAsync(graceful.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    if (!_process.HasExited)
                    {
                        _process.Kill(entireProcessTree: true);
                    }
                }
                catch (InvalidOperationException)
                {
                    // The process may have exited during termination.
                }

                try
                {
                    using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await _process.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // The OS may retain a WSL launcher briefly after pipe closure.
                }
            }
        }
        finally
        {
            _process.Dispose();
            try
            {
                await _standardErrorDrain.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or ObjectDisposedException or TimeoutException)
            {
                // stderr is drained to a sink and never exposed as application logging.
            }
        }
    }
}
