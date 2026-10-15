namespace VeilChat.Desktop.Core.Models;

public sealed record MockMessage(
    string Speaker,
    string Text,
    string TimeLabel);
