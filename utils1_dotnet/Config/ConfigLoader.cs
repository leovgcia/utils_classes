using System;
using System.IO;
using Newtonsoft.Json;
using Utils1Dotnet.Exceptions;

namespace Utils1Dotnet.Config
{
    public static class ConfigLoader
    {
        public static T LoadJsonConfig<T>(string filename)
        {
            var configFilename = Environment.GetEnvironmentVariable(filename);
            if (string.IsNullOrEmpty(configFilename)) throw new ConfigFileNotFoundError($"La variable de entorno {filename} no está definida.");
            var path = Utils1Dotnet.Utils.TextUtils.FindFile(configFilename);
            try
            {
                var txt = File.ReadAllText(path);
                return JsonConvert.DeserializeObject<T>(txt);
            }
            catch (JsonException e)
            {
                throw new ConfigParseError($"Error al parsear JSON: {e.Message}");
            }
            catch (Exception e)
            {
                throw new ConfigParseError(e.Message);
            }
        }
    }
}
