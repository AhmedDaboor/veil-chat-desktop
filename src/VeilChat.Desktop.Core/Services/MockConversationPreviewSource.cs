using VeilChat.Desktop.Core.Models;

namespace VeilChat.Desktop.Core.Services;

/// <summary>
/// Supplies static in-memory demonstration content. This service never connects to a network.
/// </summary>
public sealed class MockConversationPreviewSource : IConversationPreviewSource
{
    private static readonly IReadOnlyList<MockConversation> Conversations = Array.AsReadOnly(
    [
        new MockConversation(
            "Example conversation (mock)",
            "This preview is local sample data.",
            "10:42",
            2)
    ]);

    private static readonly IReadOnlyList<MockMessage> Messages = Array.AsReadOnly(
    [
        new MockMessage("Example contact (mock)", "This is a sample message. It was not sent or received.", "10:41"),
        new MockMessage("You (mock)", "The desktop shell is showing local demo content only.", "10:42")
    ]);

    public IReadOnlyList<MockConversation> GetConversations() => Conversations;

    public IReadOnlyList<MockMessage> GetMessages() => Messages;
}
