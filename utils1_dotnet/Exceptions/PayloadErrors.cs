namespace Utils1Dotnet.Exceptions;

public class PayloadError : Exception
{
	public string Path { get; }
	public object Issue { get; }
	public PayloadError(string message = "", string path = "$", object issue = null, Exception inner = null)
		: base(message, inner)
	{
		Path = path;
		Issue = issue;
	}
}

	public class SQLInjectionDetectedError : PayloadError { public SQLInjectionDetectedError(string message, string path = "$", object issue = null) : base(message, path, issue) { } }
	public class XSSDetectedError : PayloadError { public XSSDetectedError(string message, string path = "$", object issue = null) : base(message, path, issue) { } }
	public class InvalidCharactersError : PayloadError { public InvalidCharactersError(string message, string path = "$", object issue = null) : base(message, path, issue) { } }
	public class LengthExceededError : PayloadError { public LengthExceededError(string message, string path = "$", object issue = null) : base(message, path, issue) { } }
	public class UnicodeNormalizationChangedError : PayloadError { public UnicodeNormalizationChangedError(string message, string path = "$", object issue = null) : base(message, path, issue) { } }
	public class InvalidBytesError : PayloadError { public InvalidBytesError(string message, string path = "$", object issue = null) : base(message, path, issue) { } }
}
