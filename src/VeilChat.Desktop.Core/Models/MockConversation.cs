namespace VeilChat.Desktop.Core.Models;

public sealed record MockConversation(
    string DisplayName,
    string Preview,
    string TimeLabel,
    int UnreadCount);
