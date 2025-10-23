using System.Collections.Generic;

namespace Utils1Dotnet.Models
{
    public record Issue(
        string Path,
        string Problem,
        string Char = "",
        string Codepoint = "",
        string Category = "",
        int Count = 0,
        string Snippet = "",
        IDictionary<string, object> Extra = null
    );
}
