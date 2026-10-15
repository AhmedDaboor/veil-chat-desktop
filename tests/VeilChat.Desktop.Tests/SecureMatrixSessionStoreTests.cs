using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VeilChat.Desktop.Core.Services;
using Xunit;

namespace VeilChat.Desktop.Tests;

public sealed class SecureMatrixSessionStoreTests
{
    [Fact]
    public async Task WindowsSessionIsProtectedAtRestAndCanBeRemoved()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), "veil-chat-secure-store-" + Guid.NewGuid().ToString("N"));
        var store = new SecureMatrixSessionStore(directory);
        var sessionJson = JsonDocument.Parse("""
            {"user_id":"@alice:example.org","device_id":"DEVICE","access_token":"test-access-token","refresh_token":"test-refresh-token"}
            """);
        var session = new SecureMatrixSession(
            "https://example.org",
            sessionJson.RootElement.Clone(),
            "store-passphrase-that-is-long-enough",
            Guid.NewGuid().ToString("D"));

        try
        {
            await store.SaveAsync(session);

            var protectedFile = Path.Combine(directory, "matrix-session.dpapi");
            Assert.True(File.Exists(protectedFile));
            var protectedBytes = await File.ReadAllBytesAsync(protectedFile);
            try
            {
                var protectedText = Encoding.UTF8.GetString(protectedBytes);
                Assert.DoesNotContain("test-access-token", protectedText, StringComparison.Ordinal);
                Assert.DoesNotContain("store-passphrase-that-is-long-enough", protectedText, StringComparison.Ordinal);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }

            var loaded = await store.LoadAsync();
            Assert.NotNull(loaded);
            Assert.Equal("https://example.org", loaded.Homeserver);
            Assert.Equal("test-access-token", loaded.Session.GetProperty("access_token").GetString());
            Assert.Equal("store-passphrase-that-is-long-enough", loaded.StorePassphrase);
            Assert.Equal(session.StoreId, loaded.StoreId);

            await store.DeleteAsync();
            Assert.Null(await store.LoadAsync());
        }
        finally
        {
            sessionJson.Dispose();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public async Task WindowsSessionLoadRejectsOversizedProtectedFileWithBoundedRead()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), "veil-chat-secure-store-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var protectedFile = Path.Combine(directory, "matrix-session.dpapi");
        try
        {
            await File.WriteAllBytesAsync(protectedFile, new byte[48 * 1024 + 1024]);

            var store = new SecureMatrixSessionStore(directory);
            await Assert.ThrowsAsync<CryptographicException>(() => store.LoadAsync());
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
