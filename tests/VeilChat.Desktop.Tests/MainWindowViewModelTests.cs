using VeilChat.Desktop.Core.Services;
using VeilChat.Desktop.Core.ViewModels;
using Xunit;

namespace VeilChat.Desktop.Tests;

public sealed class MainWindowViewModelTests
{
    [Fact]
    public void StartsOnChatsWithLocalMockContent()
    {
        var viewModel = CreateViewModel();

        Assert.IsType<ChatsPageViewModel>(viewModel.CurrentPage);
        Assert.Equal("Chats", viewModel.ActiveNavigation);
        Assert.NotEmpty(viewModel.ChatsPage.Conversations);
        Assert.True(viewModel.ChatsPage.IsMockMode);
        Assert.False(viewModel.ChatsPage.CanSend);
        Assert.All(viewModel.ChatsPage.Messages, message => Assert.True(message.IsMock));
        Assert.All(viewModel.ChatsPage.Conversations, conversation =>
            Assert.Contains("(mock)", conversation.DisplayName, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task SettingsCommandRefreshesWorkerAndKeepsSecurityFeaturesDistinct()
    {
        var viewModel = CreateViewModel();

        await viewModel.ShowSettingsCommand.ExecuteAsync(null);

        Assert.Same(viewModel.SettingsPage, viewModel.CurrentPage);
        Assert.Equal("Privacy & settings", viewModel.ActiveNavigation);
        Assert.Equal("Connected — worker.hello succeeded.", viewModel.SettingsPage.WorkerConnectionState);
        Assert.Equal("matrix_sdk_available", viewModel.SettingsPage.WorkerPrivacyState);
        Assert.Equal("tor_required", viewModel.SettingsPage.WorkerNetworkAccess);
        Assert.Contains("not configured", viewModel.SettingsPage.TorState, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("includes E2EE", viewModel.SettingsPage.EncryptionState, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ChatsCommandReturnsToTheMockChatsPage()
    {
        var viewModel = CreateViewModel();

        await viewModel.ShowSettingsCommand.ExecuteAsync(null);
        viewModel.ShowChatsCommand.Execute(null);

        Assert.Same(viewModel.ChatsPage, viewModel.CurrentPage);
        Assert.Equal("Chats", viewModel.ActiveNavigation);
    }

    [Fact]
    public void OnlyKnownEncryptedDirectInvitesAreAcceptable()
    {
        Assert.True(new ChatInviteItem("!secure:example.org", true, true, true).CanAccept);
        Assert.False(new ChatInviteItem("!group:example.org", false, true, true).CanAccept);
        Assert.False(new ChatInviteItem("!plain:example.org", true, false, true).CanAccept);
        Assert.False(new ChatInviteItem("!unknown:example.org", true, true, false).CanAccept);
    }

    [Theory]
    [InlineData(MatrixPeerIdentityStatus.Verified, "Matrix SDK reports the peer identity verified")]
    [InlineData(MatrixPeerIdentityStatus.Unknown, "Peer identity status unknown")]
    [InlineData(MatrixPeerIdentityStatus.Unverified, "Peer identity not verified")]
    [InlineData(MatrixPeerIdentityStatus.PreviouslyVerified, "Previously verified")]
    [InlineData(MatrixPeerIdentityStatus.VerificationViolation, "Security warning")]
    public void RoomIdentityStatusIsDisplayedWithoutInferringTrust(
        MatrixPeerIdentityStatus status,
        string expectedText)
    {
        var conversation = new ChatConversationItem(
            "@peer:example.org",
            "Encrypted room",
            "",
            "!room:example.org",
            true,
            false,
            status);

        Assert.Contains(expectedText, conversation.PeerIdentityStatusText, StringComparison.Ordinal);
    }

    [Fact]
    public void MatrixSasIsFormattedForHumanComparisonWithoutCreatingTrust()
    {
        var verification = new MatrixPeerVerification(
            "@peer:example.org",
            "flow-123",
            "sas_ready",
            [new MatrixVerificationEmoji("🐶", "Dog"), new MatrixVerificationEmoji("🐱", "Cat")],
            [12, 345, 678],
            MatrixPeerIdentityStatus.Unverified);

        Assert.Equal("012 – 345 – 678", verification.SasDisplay);
        Assert.Equal(MatrixPeerIdentityStatus.Unverified, verification.IdentityStatus);
    }

    private static MainWindowViewModel CreateViewModel() =>
        new(new MockConversationPreviewSource(), new StubWorkerStatusService());

    private sealed class StubWorkerStatusService : IWorkerStatusService
    {
        public WorkerConnectionState ConnectionState => WorkerConnectionState.Connected;

        public Task<WorkerPrivacyStatus> GetPrivacyStatusAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new WorkerPrivacyStatus("matrix_sdk_available", "tor_required", "sdk_feature_available", "not_started"));

        public Task<WorkerTorStatus> GetTorStatusAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new WorkerTorStatus("not_configured", false));
    }
}
