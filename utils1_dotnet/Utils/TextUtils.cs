using System;
using System.IO;
using Utils1Dotnet.Exceptions;

namespace Utils1Dotnet.Utils
{
    public static class TextUtils
    {
        public static string FindFile(string nombre, string basePath = ".")
        {
            try
            {
                var baseDir = new DirectoryInfo(basePath);
                var nombreSinExt = Path.GetFileNameWithoutExtension(nombre);
                var ext = Path.GetExtension(nombre);
                var resultados = new System.Collections.Generic.List<string>();
                foreach (var file in baseDir.EnumerateFiles("*", SearchOption.AllDirectories))
                {
                    if (Path.GetFileNameWithoutExtension(file.Name) == nombreSinExt)
                    {
                        if (string.IsNullOrEmpty(ext) || Path.GetExtension(file.Name) == ext) resultados.Add(file.FullName);
                    }
                }
                if (resultados.Count == 0) throw new ConfigFileNotFoundError($"Archivo '{nombre}' no encontrado en '{basePath}'");
                return resultados[0];
            }
            catch (ConfigFileNotFoundError) { throw; }
            catch (Exception e)
            {
                throw new FindFileError(e.Message);
            }
        }
    }
}
