using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using Utils1Dotnet.Exceptions;
using Utils1Dotnet.Models;

namespace Utils1Dotnet.Services
{
    public class PayloadScanner
    {
        private readonly int MAX_LEN_PER_FIELD = 500;
        private static readonly HashSet<string> SQL_KEYWORDS = new(StringComparer.OrdinalIgnoreCase)
        {
            "select","union","insert","update","delete","drop","alter","where","from","into","values","or","and","create","table","database","exec","exists","sleep","benchmark"
        };

        private static readonly List<(int a, int b)> WEIRD_UNICODE_RANGES = new()
        {
            (0x200B, 0x200F), (0x202A, 0x202E), (0x2066, 0x2069), (0xFEFF, 0xFEFF), (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x2060, 0x2060), (0x00A0, 0x00A0), (0x180E, 0x180E)
        };

        private static readonly HashSet<char> FORBIDDEN_CHARS = new("#<>[]$%*()'`;?¿:\"=~{}@&/|·¬\\");

        private static readonly Regex[] SQL_COMMENT_PATTERNS = new Regex[] {
            new Regex("--[^\n]*", RegexOptions.Compiled),
            new Regex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.Compiled),
            new Regex("#.*", RegexOptions.Compiled)
        };

        private static readonly Regex[] XSS_PATTERNS = new Regex[] {
            new Regex("<script\\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("on\\w+\\s*=", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("javascript\\s*:", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("<img\\s+[^>]*src\\s*=\\s*['\"]?javascript:", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("<iframe\\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("<svg\\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("<meta\\s+[^>]*http-equiv", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("document\\s*\\.", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("window\\s*\\.", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("eval\\s*\\(", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("settimeout\\s*\\(", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("setinterval\\s*\\(", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("alert\\s*\\(", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex("<body\\s+onload", RegexOptions.IgnoreCase | RegexOptions.Compiled)
        };

        public PayloadScanner(int maxLen = 500)
        {
            MAX_LEN_PER_FIELD = maxLen;
        }

        private static bool IsWeirdUnicode(char ch)
        {
            var cp = (int)ch;
            foreach (var (a, b) in WEIRD_UNICODE_RANGES)
            {
                if (a <= cp && cp <= b) return true;
            }
            return false;
        }

        private static bool IsForbiddenCategory(char ch)
        {
            var cat = CharUnicodeInfo.GetUnicodeCategory(ch);
            if (cat == UnicodeCategory.Control || cat == UnicodeCategory.Format || cat == UnicodeCategory.Surrogate || cat == UnicodeCategory.PrivateUse || cat == UnicodeCategory.OtherNotAssigned)
            {
                if (ch == '\t' || ch == '\n' || ch == '\r') return false;
                return true;
            }
            return false;
        }

        private static string RemoveInvisibles(string text)
        {
            var sb = new StringBuilder(text.Length);
            foreach (var c in text)
            {
                if (!IsWeirdUnicode(c)) sb.Append(c);
            }
            return sb.ToString();
        }

        private static string NormalizeAndClean(string text)
        {
            if (text == null) return null;
            var n = text.Normalize(NormalizationForm.FormKC);
            n = RemoveInvisibles(n);
            return n;
        }

        private static List<string> Tokenize(string text)
        {
            var m = Regex.Matches(text.ToLowerInvariant(), "[a-zA-Z_]+|\\d+|[^\\w\\s]");
            return m.Select(x => x.Value).ToList();
        }

        public (bool suspicious, List<string> tokens, List<string> sqlHits, List<string> sqlComments) DetectSqlPayload(string text)
        {
            var cleaned = NormalizeAndClean(text ?? string.Empty);
            var tokens = Tokenize(cleaned);
            var sqlHits = tokens.Where(t => SQL_KEYWORDS.Contains(t)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var suspicious = sqlHits.Count >= 2 || (tokens.Contains("or") && tokens.Contains("="));
            var commentMatches = new List<string>();
            foreach (var pattern in SQL_COMMENT_PATTERNS)
            {
                var m = pattern.Match(cleaned);
                if (m.Success) commentMatches.Add(m.Value);
            }
            if (commentMatches.Count > 0) suspicious = true;
            return (suspicious, tokens, sqlHits, commentMatches);
        }

        public (bool suspicious, List<string> matchedPatterns) DetectXssPayload(string text)
        {
            var cleaned = NormalizeAndClean(text ?? string.Empty);
            var matches = new List<string>();
            foreach (var pattern in XSS_PATTERNS)
            {
                if (pattern.IsMatch(cleaned)) matches.Add(pattern.ToString());
            }
            return (matches.Count > 0, matches);
        }

        public List<Issue> ScanString(string path, string s)
        {
            var issues = new List<Issue>();
            s ??= string.Empty;
            if (s.Length > MAX_LEN_PER_FIELD)
            {
                var issue = new Issue(path, "length_exceeded", string.Empty, string.Empty, string.Empty, s.Length, string.Empty, new Dictionary<string, object>{{"max", MAX_LEN_PER_FIELD}});
                issues.Add(issue);
            }

            var n = s.Normalize(NormalizationForm.FormC);
            if (n != s)
            {
                var issue = new Issue(path, "unicode_normalization_changed", string.Empty, string.Empty, string.Empty, 0, string.Empty, new Dictionary<string, object>{{"original_len", s.Length},{"normalized_len", n.Length}});
                issues.Add(issue);
                throw new UnicodeNormalizationChangedError("Texto Unicode normalizado", path, issue);
            }
            s = n;

            var sqlCheck = DetectSqlPayload(s);
            if (sqlCheck.suspicious)
            {
                var issue = new Issue(path, "sql_injection_like_payload", string.Empty, string.Empty, string.Empty, 0, s.Length > 30 ? s.Substring(0, 30) : s, new Dictionary<string, object>{{"sql_tokens_detected", sqlCheck.sqlHits},{"sql_comment_patterns", sqlCheck.sqlComments},{"tokens", sqlCheck.tokens}});
                throw new SQLInjectionDetectedError("Posible payload SQL detectado", path, issue);
            }

            var xssCheck = DetectXssPayload(s);
            if (xssCheck.suspicious)
            {
                var issue = new Issue(path, "xss_like_payload", string.Empty, string.Empty, string.Empty, 0, s.Length > 30 ? s.Substring(0, 30) : s, new Dictionary<string, object>{{"matched_patterns", xssCheck.matchedPatterns}});
                throw new XSSDetectedError("Posible payload XSS detectado", path, issue);
            }

            var counter = new Dictionary<char, int>();
            foreach (var ch in s)
            {
                if (!counter.ContainsKey(ch)) counter[ch] = 0;
                counter[ch]++;
            }
            foreach (var kv in counter)
            {
                var ch = kv.Key;
                var cnt = kv.Value;
                var cp = $"U+{(int)ch:X4}";
                var cat = CharUnicodeInfo.GetUnicodeCategory(ch).ToString();
                if (FORBIDDEN_CHARS.Contains(ch) || IsWeirdUnicode(ch) || IsForbiddenCategory(ch))
                {
                    var issue = new Issue(path, "invalid_char_detected", ch.ToString(), cp, cat, cnt, string.Empty, null);
                    throw new InvalidCharactersError("Caracter inválido detectado", path, issue);
                }
            }

            return issues;
        }

        public List<Issue> Walk(JToken token, string path = "$")
        {
            var issues = new List<Issue>();
            if (token == null) return issues;
            if (token.Type == JTokenType.Object)
            {
                foreach (var prop in token.Children<JProperty>())
                {
                    var k = prop.Name;
                    var k_s = k;
                    if (k_s == null)
                    {
                        var issue = new Issue($"{path}.<key>", "invalid_bytes_key");
                        issues.Add(issue);
                        throw new InvalidBytesError("Clave no válida (bytes)", $"{path}.<key>", issue);
                    }
                    else
                    {
                        issues.AddRange(ScanString($"{path}[\"{k_s}\"]<key>", k_s));
                    }
                    issues.AddRange(Walk(prop.Value, $"{path}[\"{k}\"]"));
                }
            }
            else if (token.Type == JTokenType.Array)
            {
                var idx = 0;
                foreach (var item in token.Children())
                {
                    issues.AddRange(Walk(item, $"{path}[{idx}]") );
                    idx++;
                }
            }
            else
            {
                var s = token.Type == JTokenType.Bytes ? null : token.ToString();
                if (s == null)
                {
                    var issue = new Issue(path, "invalid_bytes_value");
                    issues.Add(issue);
                    throw new InvalidBytesError("Valor no válido (bytes)", path, issue);
                }
                issues.AddRange(ScanString(path, s));
            }
            return issues;
        }

        public JObject ValidateExtendedPayload(JToken dato)
        {
            var issues = Walk(dato);
            var obj = new JObject();
            obj["valido"] = issues.Count == 0;
            obj["errores"] = new JArray(issues.Select(i => i.Problem));
            obj["detalles"] = JArray.FromObject(issues);
            return obj;
        }
    }
}
