using VeilChat.Desktop.Core.Models;

namespace VeilChat.Desktop.Core.Services;

public interface IConversationPreviewSource
{
    IReadOnlyList<MockConversation> GetConversations();

    IReadOnlyList<MockMessage> GetMessages();
}
