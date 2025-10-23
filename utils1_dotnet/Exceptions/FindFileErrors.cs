using System;

namespace Utils1Dotnet.Exceptions
{
	public class FindFileError : Exception
	{
		public FindFileError(string message = "Ocurrió un error al buscar un archivo:", Exception inner = null)
			: base(message, inner)
		{
		}
	}

	public class ConfigFileNotFoundError : FindFileError
	{
		public ConfigFileNotFoundError(string message) : base(message) { }
	}

	public class ConfigParseError : FindFileError
	{
		public ConfigParseError(string message) : base(message) { }
	}
}
