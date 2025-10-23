using System;
using Utils1Dotnet.Exceptions;

namespace Utils1Dotnet.Services.Security
{
    public class PasswordManager
    {
        public PasswordManager() { }

        public string HashPassword(string password)
        {
            if (password is null) throw new PasswordHashError("Password debe ser string");
            try
            {
                return BCrypt.Net.BCrypt.HashPassword(password);
            }
            catch (PasswordHashError)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PasswordHashError($"Error al hashear password: {e.Message}");
            }
        }

        public bool VerifyPassword(string password, string hashed)
        {
            if (password is null || hashed is null) throw new PasswordHashError("Tipos inválidos para verify_password");
            try
            {
                return BCrypt.Net.BCrypt.Verify(password, hashed);
            }
            catch (Exception e)
            {
                throw new PasswordHashError($"Error verificando password: {e.Message}");
            }
        }
    }
}
