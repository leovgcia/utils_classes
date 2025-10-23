using System;
using Utils1Dotnet.Exceptions;

namespace Utils1Dotnet.Services.Security
{
    public class Obfuscator
    {
        public Obfuscator() { }

        public string CaesarCipher(string text, int shift = 2)
        {
            try
            {
                var chars = text.ToCharArray();
                for (int i = 0; i < chars.Length; i++)
                {
                    var c = chars[i];
                    if (char.IsLetter(c))
                    {
                        var baseChar = char.IsUpper(c) ? 'A' : 'a';
                        chars[i] = (char)((((c - baseChar) + shift) % 26 + 26) % 26 + baseChar);
                    }
                }
                return new string(chars);
            }
            catch (Exception e)
            {
                throw new ObfuscationError($"Error en caesar_cipher: {e.Message}");
            }
        }

        public string CaesarDecipher(string text, int shift = 2) => CaesarCipher(text, -shift);
        public string ObfuscateJwt(string token, int shift = 2) => CaesarCipher(token, shift);
        public string DeobfuscateJwt(string obf, int shift = 2) => CaesarDecipher(obf, shift);
    }
}
