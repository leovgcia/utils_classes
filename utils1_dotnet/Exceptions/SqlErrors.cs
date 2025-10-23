using System;

namespace Utils1Dotnet.Exceptions
{
	public class SqlError : Exception
	{
		public SqlError(string message = "Ocurrió un error durante la instrucción sql:", Exception inner = null)
			: base(message, inner) { }
	}
}
