using System;
using Utils1Dotnet.Exceptions;
using System.Collections.Generic;

namespace Utils1Dotnet.Services.Security
{
    public class RequestValidator
    {
        private static readonly string[] REQUIRED_GET_HEADERS = new[] { "Accept-Language", "User-Agent" };

        public RequestValidator() { }

        public bool IsGetRequestValid(IDictionary<string, string> headers)
        {
            try
            {
                foreach (var h in REQUIRED_GET_HEADERS)
                {
                    if (!headers.ContainsKey(h) || string.IsNullOrEmpty(headers[h]))
                    {
                        return false;
                    }
                }
                return true;
            }
            catch (Exception e)
            {
                throw new RequestValidationError($"Error validando GET request: {e.Message}");
            }
        }

        public bool IsPostRequestValid(IDictionary<string, string> headers, Func<string> getJson = null, bool requireJson = true)
        {
            try
            {
                if (!headers.ContainsKey("Content-Type") || string.IsNullOrEmpty(headers["Content-Type"]))
                    throw new MissingHeaderError("Content-Type faltante en POST request");
                if (requireJson)
                {
                    if (getJson == null) throw new BadRequestPayloadError("Objeto request no soporta get_json()");
                    var payload = getJson();
                    if (string.IsNullOrEmpty(payload)) return false;
                }
                return true;
            }
            catch (RequestValidationError) { throw; }
            catch (Exception e)
            {
                throw new RequestValidationError($"Error validando POST request: {e.Message}");
            }
        }
    }
}
