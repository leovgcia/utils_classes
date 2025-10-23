using System;
using Utils1Dotnet.Exceptions;

namespace Utils1Dotnet.Services.Security
{
    public class SecurityManager
    {
        public JWTManager Jwt { get; }
        public Obfuscator Obfuscator { get; }
        public PasswordManager Pw { get; }
        public RequestValidator Validator { get; }

        public SecurityManager(string jwtSecret = null)
        {
            try
            {
                Jwt = new JWTManager(jwtSecret);
                Obfuscator = new Obfuscator();
                Pw = new PasswordManager();
                Validator = new RequestValidator();
            }
            catch (Exception e)
            {
                throw new SecurityError($"Error inicializando SecurityManager: {e.Message}");
            }
        }

        public string FirmarRenderizado(System.Collections.Generic.IDictionary<string, object> payload, TimeSpan? expires = null, bool obfuscate = true, int shift = 2)
        {
            var token = Jwt.Encode(payload, expires);
            return obfuscate ? Obfuscator.ObfuscateJwt(token, shift) : token;
        }

        public System.Collections.Generic.IDictionary<string, object> ComprobarRenderizado(string tokenOrObf, bool obfuscated = true, int shift = 2)
        {
            try
            {
                var token = obfuscated ? Obfuscator.DeobfuscateJwt(tokenOrObf, shift) : tokenOrObf;
                return Jwt.Decode(token);
            }
            catch (JWTError) { throw; }
            catch (ObfuscationError) { throw; }
            catch (Exception e)
            {
                throw new SecurityError($"Error comprobando renderizado: {e.Message}");
            }
        }

        public string EncriptarPassword(string password) => Pw.HashPassword(password);
        public bool VerificarPassword(string password, string hashed) => Pw.VerifyPassword(password, hashed);
        public bool IsGetRequestValid(System.Collections.Generic.IDictionary<string, string> headers) => Validator.IsGetRequestValid(headers);
        public bool IsPostRequestValid(System.Collections.Generic.IDictionary<string, string> headers, Func<string> getJson = null, bool requireJson = true) => Validator.IsPostRequestValid(headers, getJson, requireJson);
        public string GenCadena(int length = 12)
        {
            var rng = new Random();
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var buf = new char[length];
            for (int i = 0; i < length; i++) buf[i] = chars[rng.Next(chars.Length)];
            return new string(buf);
        }

        public int GenSegundos(int minSecs = 3, int maxSecs = 5)
        {
            var rng = new Random();
            return rng.Next(minSecs, maxSecs + 1);
        }
    }
}
