using System;
using Utils1Dotnet.Exceptions;

namespace Utils1Dotnet.Services
{
    public class TimeManager
    {
        private readonly TimeZoneInfo _localZone;
        private readonly TimeZoneInfo _utcZone;
        private readonly int _jwtExpDays;

        public TimeManager()
        {
            try
            {
                _localZone = TimeZoneInfo.Local;
                _utcZone = TimeZoneInfo.Utc;
                var s = Environment.GetEnvironmentVariable("JWT_EXP_DAYS") ?? "30";
                _jwtExpDays = int.TryParse(s, out var v) ? v : 30;
            }
            catch (Exception e)
            {
                throw new TimeManagerError($"Error inicializando zonas horarias o JWT_EXP_DAYS: {e.Message}");
            }
        }

        public string GetTimestamp(TimeZoneInfo tz = null, string fmt = "ddd, MMMM d, yyyy, HH:mm:ss")
        {
            tz ??= _localZone;
            try
            {
                var now = TimeZoneInfo.ConvertTime(DateTime.UtcNow, _utcZone, tz);
                return now.ToString(fmt);
            }
            catch (Exception e)
            {
                throw new TimeManagerError($"No se pudo obtener timestamp: {e.Message}");
            }
        }

        public long GetTimestampEpoch(TimeZoneInfo tz = null)
        {
            tz ??= _utcZone;
            try
            {
                var now = TimeZoneInfo.ConvertTime(DateTime.UtcNow, _utcZone, tz);
                var dto = new DateTimeOffset(now);
                return dto.ToUnixTimeSeconds();
            }
            catch (Exception e)
            {
                throw new TimeManagerError($"No se pudo obtener timestamp epoch: {e.Message}");
            }
        }

        public string GetTimestampIso(TimeZoneInfo tz = null)
        {
            tz ??= _localZone;
            try
            {
                var now = TimeZoneInfo.ConvertTime(DateTime.UtcNow, _utcZone, tz);
                return now.ToString("o");
            }
            catch (Exception e)
            {
                throw new TimeManagerError($"No se pudo obtener timestamp ISO: {e.Message}");
            }
        }

        public DateTime GetJwtExpirationDate(int? days = null, int hours = 0, int minutes = 0, int seconds = 0)
        {
            try
            {
                if (!days.HasValue && hours == 0 && minutes == 0 && seconds == 0) days = _jwtExpDays;
                var now = DateTime.UtcNow;
                return now.AddDays(days ?? 0).AddHours(hours).AddMinutes(minutes).AddSeconds(seconds);
            }
            catch (Exception e)
            {
                throw new TimeManagerError($"No se pudo calcular expiración JWT: {e.Message}");
            }
        }

        public long GetJwtExpirationTimestamp(int? days = null, int hours = 0, int minutes = 0, int seconds = 0)
        {
            try
            {
                var exp = GetJwtExpirationDate(days, hours, minutes, seconds);
                var dto = new DateTimeOffset(exp, TimeSpan.Zero);
                return dto.ToUnixTimeSeconds();
            }
            catch (Exception e)
            {
                throw new TimeManagerError($"No se pudo calcular timestamp de expiración JWT: {e.Message}");
            }
        }
    }
}
