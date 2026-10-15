using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VeilChat.Desktop.Core.Services;

/// <summary>Contains credentials that must only be held in OS-protected storage.</summary>
public sealed record SecureMatrixSession(string Homeserver, JsonElement Session, string StorePassphrase, string StoreId);

public interface ISecureMatrixSessionStore
{
    Task SaveAsync(SecureMatrixSession session, CancellationToken cancellationToken = default);

    Task<SecureMatrixSession?> LoadAsync(CancellationToken cancellationToken = default);

    Task DeleteAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Stores session tokens and the SDK crypto-store passphrase using Windows
/// current-user DPAPI or the Linux desktop Secret Service. There is no plaintext
/// file fallback when the OS store is unavailable.
/// </summary>
public sealed class SecureMatrixSessionStore : ISecureMatrixSessionStore
{
    private const int MaxSecretBytes = 48 * 1024;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("VeilChat.MatrixSession.v1");
    private readonly string _dataDirectory;
    private readonly string _protectedFile;

    public SecureMatrixSessionStore(string dataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        if (!Path.IsPathFullyQualified(dataDirectory))
        {
            throw new ArgumentException("The secure-store directory must be absolute.", nameof(dataDirectory));
        }
        _dataDirectory = dataDirectory;
        _protectedFile = Path.Combine(dataDirectory, "matrix-session.dpapi");
    }

    public async Task SaveAsync(SecureMatrixSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var plainText = JsonSerializer.SerializeToUtf8Bytes(session);
        try
        {
            if (plainText.Length > MaxSecretBytes)
            {
                throw new InvalidOperationException("The secure session record exceeds its size limit.");
            }

            if (OperatingSystem.IsWindows())
            {
                var protectedBytes = Dpapi.Protect(plainText, Entropy);
                try
                {
                    Directory.CreateDirectory(_dataDirectory);
                    var temporaryFile = _protectedFile + ".tmp-" + Guid.NewGuid().ToString("N");
                    try
                    {
                        await File.WriteAllBytesAsync(temporaryFile, protectedBytes, cancellationToken).ConfigureAwait(false);
                        File.Move(temporaryFile, _protectedFile, overwrite: true);
                    }
                    finally
                    {
                        if (File.Exists(temporaryFile))
                        {
                            File.Delete(temporaryFile);
                        }
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(protectedBytes);
                }
                return;
            }

            if (OperatingSystem.IsLinux())
            {
                await RunSecretToolAsync("store", plainText, cancellationToken).ConfigureAwait(false);
                return;
            }

            throw new PlatformNotSupportedException("No supported OS secure store is available.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainText);
        }
    }

    public async Task<SecureMatrixSession?> LoadAsync(CancellationToken cancellationToken = default)
    {
        byte[]? plainText = null;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                if (!File.Exists(_protectedFile))
                {
                    return null;
                }

                byte[] protectedBytes;
                await using (var protectedFile = new FileStream(
                    _protectedFile,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 4096,
                    FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    try
                    {
                        protectedBytes = await ReadBoundedAsync(
                            protectedFile,
                            MaxSecretBytes,
                            cancellationToken).ConfigureAwait(false);
                    }
                    catch (InvalidOperationException exception)
                    {
                        throw new CryptographicException("Stored session is invalid.", exception);
                    }
                }
                try
                {
                    plainText = Dpapi.Unprotect(protectedBytes, Entropy);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(protectedBytes);
                }
            }
            else if (OperatingSystem.IsLinux())
            {
                plainText = await RunSecretToolAsync("lookup", null, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                throw new PlatformNotSupportedException("No supported OS secure store is available.");
            }

            if (plainText.Length == 0)
            {
                return null;
            }
            return JsonSerializer.Deserialize<SecureMatrixSession>(plainText);
        }
        finally
        {
            if (plainText is not null)
            {
                CryptographicOperations.ZeroMemory(plainText);
            }
        }
    }

    public async Task DeleteAsync(CancellationToken cancellationToken = default)
    {
        if (OperatingSystem.IsWindows())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (File.Exists(_protectedFile))
            {
                File.Delete(_protectedFile);
            }
            return;
        }

        if (OperatingSystem.IsLinux())
        {
            await RunSecretToolAsync("clear", null, cancellationToken).ConfigureAwait(false);
            return;
        }

        throw new PlatformNotSupportedException("No supported OS secure store is available.");
    }

    private static async Task<byte[]> RunSecretToolAsync(
        string operation,
        byte[]? input,
        CancellationToken cancellationToken)
    {
        var executable = new[] { "/usr/bin/secret-tool", "/bin/secret-tool" }.FirstOrDefault(File.Exists)
            ?? throw new InvalidOperationException("Linux Secret Service client is unavailable.");
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.Environment.Clear();
        foreach (var name in new[] { "PATH", "HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS" })
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrWhiteSpace(value))
            {
                startInfo.Environment[name] = value;
            }
            else
            {
                startInfo.Environment.Remove(name);
            }
        }

        startInfo.ArgumentList.Add(operation);
        if (operation == "store")
        {
            startInfo.ArgumentList.Add("--label=Veil Chat session");
        }
        else if (operation == "lookup")
        {
            startInfo.ArgumentList.Add("application");
            startInfo.ArgumentList.Add("veil-chat");
            startInfo.ArgumentList.Add("record");
            startInfo.ArgumentList.Add("matrix-session-v1");
        }
        else if (operation != "clear")
        {
            throw new ArgumentOutOfRangeException(nameof(operation));
        }
        if (operation != "lookup")
        {
            startInfo.ArgumentList.Add("application");
            startInfo.ArgumentList.Add("veil-chat");
            startInfo.ArgumentList.Add("record");
            startInfo.ArgumentList.Add("matrix-session-v1");
        }

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidOperationException("Linux Secret Service request could not start.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        var stderrDrain = process.StandardError.BaseStream.CopyToAsync(Stream.Null, timeout.Token);
        byte[] output;
        try
        {
            if (input is not null)
            {
                await process.StandardInput.BaseStream.WriteAsync(input, timeout.Token).ConfigureAwait(false);
                await process.StandardInput.BaseStream.FlushAsync(timeout.Token).ConfigureAwait(false);
            }
            process.StandardInput.Close();
            output = await ReadBoundedAsync(process.StandardOutput.BaseStream, MaxSecretBytes, timeout.Token).ConfigureAwait(false);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            await stderrDrain.ConfigureAwait(false);
        }
        catch
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException)
            {
            }
            throw;
        }

        if (process.ExitCode != 0)
        {
            CryptographicOperations.ZeroMemory(output);
            if ((operation is "lookup" or "clear") && process.ExitCode == 1)
            {
                return [];
            }
            throw new InvalidOperationException("Linux Secret Service request failed.");
        }
        return output;
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, int maximumBytes, CancellationToken cancellationToken)
    {
        var output = new byte[maximumBytes];
        var length = 0;
        var buffer = new byte[1024];
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                if (length + read > maximumBytes)
                {
                    throw new InvalidOperationException("OS secure-store output exceeded its limit.");
                }
                buffer.AsSpan(0, read).CopyTo(output.AsSpan(length));
                length += read;
            }
            return output.AsSpan(0, length).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(output);
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static class Dpapi
    {
        private const uint UiForbidden = 0x1;

        [StructLayout(LayoutKind.Sequential)]
        private struct DataBlob
        {
            public int Length;
            public IntPtr Data;
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectData(
            ref DataBlob input,
            string? description,
            ref DataBlob entropy,
            IntPtr reserved,
            IntPtr prompt,
            uint flags,
            out DataBlob output);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectData(
            ref DataBlob input,
            IntPtr description,
            ref DataBlob entropy,
            IntPtr reserved,
            IntPtr prompt,
            uint flags,
            out DataBlob output);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static byte[] Protect(byte[] input, byte[] entropy) => Transform(input, entropy, protect: true);

        public static byte[] Unprotect(byte[] input, byte[] entropy) => Transform(input, entropy, protect: false);

        private static byte[] Transform(byte[] input, byte[] entropy, bool protect)
        {
            var inputBlob = Allocate(input);
            var entropyBlob = Allocate(entropy);
            try
            {
                var success = protect
                    ? CryptProtectData(ref inputBlob, "Veil Chat session", ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out var outputBlob)
                    : CryptUnprotectData(ref inputBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, out outputBlob);
                if (!success)
                {
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                }
                try
                {
                    var output = new byte[outputBlob.Length];
                    Marshal.Copy(outputBlob.Data, output, 0, output.Length);
                    return output;
                }
                finally
                {
                    ZeroMemory(outputBlob.Data, outputBlob.Length);
                    _ = LocalFree(outputBlob.Data);
                }
            }
            finally
            {
                ZeroAndFree(ref inputBlob);
                ZeroAndFree(ref entropyBlob);
            }
        }

        private static DataBlob Allocate(byte[] bytes)
        {
            var data = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, data, bytes.Length);
            return new DataBlob { Length = bytes.Length, Data = data };
        }

        private static void ZeroAndFree(ref DataBlob blob)
        {
            if (blob.Data != IntPtr.Zero)
            {
                ZeroMemory(blob.Data, blob.Length);
                Marshal.FreeHGlobal(blob.Data);
                blob.Data = IntPtr.Zero;
                blob.Length = 0;
            }
        }

        private static void ZeroMemory(IntPtr data, int length)
        {
            for (var index = 0; index < length; index++)
            {
                Marshal.WriteByte(data, index, 0);
            }
        }
    }
}
