using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Utils1Dotnet.Exceptions;
using System.Collections.Generic;

namespace Utils1Dotnet.Services
{
    public class JWTManager
    {
        private readonly string _secret;
        private readonly string _algorithm;

        public JWTManager(string secret = null, string algorithm = "HS256")
        {
            _secret = secret ?? Environment.GetEnvironmentVariable("JWT_SECRET") ?? Environment.GetEnvironmentVariable("JWK_SECRET");
            if (string.IsNullOrEmpty(_secret)) throw new JWTError("No se encontró secreto JWT en entorno (JWT_SECRET/JWK_SECRET).");
            _algorithm = algorithm;
        }

        public string Encode(IDictionary<string, object> payload, TimeSpan? expires = null)
        {
            try
            {
                var claims = new List<Claim>();
                foreach (var kv in payload)
                {
                    if (kv.Value is string s)
                        claims.Add(new Claim(kv.Key, s));
                    else
                        claims.Add(new Claim(kv.Key, kv.Value?.ToString() ?? string.Empty));
                }

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var now = DateTime.UtcNow;
                var tokenHandler = new JwtSecurityTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims),
                    Expires = expires.HasValue ? now.Add(expires.Value) : (DateTime?)null,
                    SigningCredentials = creds
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }
            catch (Exception e)
            {
                throw new JWTEncodeError($"Error al codificar JWT: {e.Message}");
            }
        }

        public IDictionary<string, object> Decode(string token, bool validateExp = true)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_secret);
                var parameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateLifetime = validateExp
                };

                tokenHandler.ValidateToken(token, parameters, out var validatedToken);
                var jwt = validatedToken as JwtSecurityToken;
                var dict = new Dictionary<string, object>();
                if (jwt != null)
                {
                    foreach (var claim in jwt.Claims)
                    {
                        dict[claim.Type] = claim.Value;
                    }
                }
                return dict;
            }
            catch (SecurityTokenExpiredException e)
            {
                throw new JWTDecodeError($"Token expirado: {e.Message}");
            }
            catch (Exception e)
            {
                throw new JWTDecodeError($"Error al decodificar JWT: {e.Message}");
            }
        }
    }
}
