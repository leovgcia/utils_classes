using System;

namespace Utils1Dotnet.Exceptions
{
	public class MapApplicationsError : Exception
	{
		public MapApplicationsError(string message = "Ocurrió un error al incorporar una aplicación:", Exception inner = null)
			: base(message, inner) { }
	}

	public class InvalidBlueprintError : MapApplicationsError
	{
		public InvalidBlueprintError(string message) : base(message) { }
	}

	public class BlueprintImportError : MapApplicationsError
	{
		public BlueprintImportError(string message) : base(message) { }
	}
}
