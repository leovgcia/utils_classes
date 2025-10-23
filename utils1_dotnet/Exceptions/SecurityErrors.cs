using System;

namespace Utils1Dotnet.Exceptions
{
	public class SecurityError : Exception
	{
		public string Caller { get; }
		public SecurityError(string message = "", string caller = null, Exception inner = null)
			: base(message, inner)
		{
			Caller = caller;
		}
	}

	public class JWTError : SecurityError { public JWTError(string message) : base(message) { } }
	public class JWTEncodeError : JWTError { public JWTEncodeError(string message) : base(message) { } }
	public class JWTDecodeError : JWTError { public JWTDecodeError(string message) : base(message) { } }
	public class RequestValidationError : SecurityError { public RequestValidationError(string message) : base(message) { } }
	public class MissingHeaderError : RequestValidationError { public MissingHeaderError(string message) : base(message) { } }
	public class InvalidContentTypeError : RequestValidationError { public InvalidContentTypeError(string message) : base(message) { } }
	public class BadRequestPayloadError : RequestValidationError { public BadRequestPayloadError(string message) : base(message) { } }
	public class ObfuscationError : SecurityError { public ObfuscationError(string message) : base(message) { } }
	public class PasswordHashError : SecurityError { public PasswordHashError(string message) : base(message) { } }
}
