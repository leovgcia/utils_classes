using System;

namespace Utils1Dotnet.Exceptions
{
	public class TimeManagerError : Exception
	{
		public string Caller { get; }
		public TimeManagerError(string message = "Error ocurrido en TimeManager: ", string caller = null, Exception inner = null)
			: base(message, inner)
		{
			Caller = caller;
		}
	}
}
