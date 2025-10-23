using System;
using System.Collections.Generic;
using Npgsql;
using Utils1Dotnet.Exceptions;

namespace Utils1Dotnet.Services
{
    public class SqlManager
    {
        private readonly string _connString;

        public SqlManager()
        {
            var dbName = Environment.GetEnvironmentVariable("DB_NAME");
            var dbUser = Environment.GetEnvironmentVariable("DB_USER");
            var dbPass = Environment.GetEnvironmentVariable("DB_PASSWORD");
            var dbHost = Environment.GetEnvironmentVariable("DB_HOST") ?? "localhost";
            var dbPort = Environment.GetEnvironmentVariable("DB_PORT") ?? "5432";

            _connString = $"Host={dbHost};Port={dbPort};Username={dbUser};Password={dbPass};Database={dbName}";
        }

        public List<Dictionary<string, object>> Query(string sql, IDictionary<string, object> parameters = null, bool fetch = false)
        {
            try
            {
                using var conn = new NpgsqlConnection(_connString);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = sql;
                if (parameters != null)
                {
                    foreach (var kv in parameters)
                    {
                        cmd.Parameters.AddWithValue(kv.Key, kv.Value ?? DBNull.Value);
                    }
                }
                using var reader = cmd.ExecuteReader();
                var results = new List<Dictionary<string, object>>();
                if (fetch)
                {
                    while (reader.Read())
                    {
                        var row = new Dictionary<string, object>();
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
                        }
                        results.Add(row);
                    }
                }
                conn.Close();
                return results;
            }
            catch (Exception e)
            {
                throw new SqlError(e.Message);
            }
        }
    }
}
