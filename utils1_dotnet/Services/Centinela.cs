using System;
using System.Collections.Generic;
using System.Diagnostics;
using Utils1Dotnet.Exceptions;

namespace Utils1Dotnet.Services
{
    public class Centinela
    {
        private readonly int _checkIntervalSeconds;
        private readonly string _diskPath;
        private readonly double _diskFreeWarningPct;
        private readonly double _cpuWarningPct;
        private readonly double _ramWarningPct;
        private readonly int _fdWarningThreshold;
        private readonly List<string> _workerNames;
        private readonly int _workerMinCount;
        private readonly string _internetCheckHost;
        private readonly int _internetTimeout;

        public Centinela()
        {
            _checkIntervalSeconds = int.Parse(Environment.GetEnvironmentVariable("CENTINELA_CHECK_INTERVAL_SECONDS") ?? "60");
            _diskPath = Environment.GetEnvironmentVariable("CENTINELA_DISK_PATH") ?? "/";
            _diskFreeWarningPct = double.Parse(Environment.GetEnvironmentVariable("CENTINELA_DISK_FREE_WARNING_PCT") ?? "10");
            _cpuWarningPct = double.Parse(Environment.GetEnvironmentVariable("CENTINELA_CPU_WARNING_PCT") ?? "90");
            _ramWarningPct = double.Parse(Environment.GetEnvironmentVariable("CENTINELA_RAM_WARNING_PCT") ?? "90");
            _fdWarningThreshold = int.Parse(Environment.GetEnvironmentVariable("CENTINELA_FD_WARNING_THRESHOLD") ?? "100");
            _workerNames = new List<string>{"myworker","celery","gunicorn"};
            _workerMinCount = int.Parse(Environment.GetEnvironmentVariable("CENTINELA_WORKER_MIN_COUNT") ?? "1");
            _internetCheckHost = "1.1.1.1";
            _internetTimeout = int.Parse(Environment.GetEnvironmentVariable("CENTINELA_INTERNET_TIMEOUT") ?? "2");
        }

        public string NowIso() => DateTime.UtcNow.ToString("o");

        public bool CheckInternet()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ping",
                    Arguments = $"-c 1 {_internetCheckHost}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var p = Process.Start(psi);
                p.WaitForExit(_internetTimeout * 1000);
                return p.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        public Dictionary<string, object> CheckDisk()
        {
            try
            {
                var di = new System.IO.DriveInfo(_diskPath);
                var total = di.TotalSize;
                var free = di.TotalFreeSpace;
                var used = total - free;
                var freePct = (double)free / total * 100.0;
                return new Dictionary<string, object>{{"total", total},{"used", used},{"free", free},{"free_pct", freePct}};
            }
            catch (Exception e)
            {
                return new Dictionary<string, object>{{"error", e.Message}};
            }
        }

        public Dictionary<string, object> CheckCpu()
        {
            try
            {
                var cpu = new PerformanceCounter("Processor", "% Processor Time", "_Total", true);
                cpu.NextValue();
                System.Threading.Thread.Sleep(500);
                var val = cpu.NextValue();
                return new Dictionary<string, object>{{"cpu_pct", val}};
            }
            catch (Exception e)
            {
                return new Dictionary<string, object>{{"error", e.Message}};
            }
        }

        public Dictionary<string, object> CheckRam()
        {
            try
            {
                var pc = new PerformanceCounter("Memory", "Available Bytes");
                var available = pc.NextValue();
                var total = new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory;
                var used = total - (long)available;
                var ramPct = (double)used / total * 100.0;
                return new Dictionary<string, object>{{"ram_pct", ramPct},{"total", total},{"available", available}};
            }
            catch (Exception e)
            {
                return new Dictionary<string, object>{{"error", e.Message}};
            }
        }

        public Dictionary<string, object> CheckFdsUnix()
        {
            try
            {
                if (System.IO.File.Exists("/proc/sys/fs/file-nr"))
                {
                    var txt = System.IO.File.ReadAllText("/proc/sys/fs/file-nr");
                    var parts = txt.Trim().Split();
                    if (parts.Length >= 3)
                    {
                        var allocated = long.Parse(parts[0]);
                        var unused = long.Parse(parts[1]);
                        var max = long.Parse(parts[2]);
                        var used = allocated - unused;
                        var free = max - used;
                        return new Dictionary<string, object>{{"max", max},{"used", used},{"free", free}};
                    }
                }
                return new Dictionary<string, object>{{"approx_open_fds", -1}};
            }
            catch (Exception e)
            {
                return new Dictionary<string, object>{{"error", e.Message}};
            }
        }

        public Dictionary<string, object> CountWorkers()
        {
            var matches = new List<Dictionary<string, object>>();
            try
            {
                var procs = Process.GetProcesses();
                foreach (var p in procs)
                {
                    try
                    {
                        var pname = p.ProcessName.ToLower();
                        var cmd = p.MainModule?.ModuleName?.ToLower() ?? "";
                        foreach (var name in _workerNames)
                        {
                            if (pname.Contains(name) || cmd.Contains(name))
                            {
                                matches.Add(new Dictionary<string, object>{{"pid", p.Id},{"name", p.ProcessName}});
                                break;
                            }
                        }
                    }
                    catch { continue; }
                }
                return new Dictionary<string, object>{{"count", matches.Count},{"matches", matches}};
            }
            catch (Exception e)
            {
                return new Dictionary<string, object>{{"error", e.Message}};
            }
        }

        public void ClassifyAndLog(string checkName, Dictionary<string, object> data)
        {
            var timestamp = NowIso();
            var level = "INFO";
            string msg = "";
            if (checkName == "internet")
            {
                var ok = data is not null && data.ContainsKey("ok") ? (bool)data["ok"] : false;
                if (!ok) { level = "WARNING"; msg = "No internet (connection failed)"; } else msg = "Internet OK";
            }
            else if (checkName == "disk")
            {
                if (data.ContainsKey("error")) { level = "ERROR"; msg = $"Disk check error: {data["error"]}"; }
                else { var freePct = Convert.ToDouble(data["free_pct"]); msg = $"Disk free {freePct:F1}%"; if (freePct < _diskFreeWarningPct) level = "WARNING"; }
            }
            else if (checkName == "cpu")
            {
                if (data.ContainsKey("error")) { level = "ERROR"; msg = $"CPU check error: {data["error"]}"; }
                else { var cpuPct = Convert.ToDouble(data["cpu_pct"]); msg = $"CPU usage {cpuPct:F1}%"; if (cpuPct > _cpuWarningPct) level = "WARNING"; }
            }
            else if (checkName == "ram")
            {
                if (data.ContainsKey("error")) { level = "ERROR"; msg = $"RAM check error: {data["error"]}"; }
                else { var ramPct = Convert.ToDouble(data["ram_pct"]); msg = $"RAM usage {ramPct:F1}%"; if (ramPct > _ramWarningPct) level = "WARNING"; }
            }
            else if (checkName == "fds")
            {
                if (data.ContainsKey("error")) { level = "ERROR"; msg = $"FDs check error: {data["error"]}"; }
                else if (data.ContainsKey("free")) { var free = data["free"]; msg = $"FDs free: {free}"; if (free is long f && f < _fdWarningThreshold) level = "WARNING"; }
                else msg = $"FDs approx open: {data.GetValueOrDefault("approx_open_fds")}";
            }
            else if (checkName == "workers")
            {
                var cnt = data.ContainsKey("count") ? Convert.ToInt32(data["count"]) : 0;
                msg = $"Workers found: {cnt}";
                if (cnt < _workerMinCount) { level = "WARNING"; msg += " (below expected)"; }
            }
            Console.WriteLine($"[{timestamp}] {level,-7} {checkName,-10} - {msg}");
        }

        public void RunCycle()
        {
            var internetOk = CheckInternet();
            ClassifyAndLog("internet", new Dictionary<string, object>{{"ok", internetOk}});
            var disk = CheckDisk(); ClassifyAndLog("disk", disk);
            var cpu = CheckCpu(); ClassifyAndLog("cpu", cpu);
            var ram = CheckRam(); ClassifyAndLog("ram", ram);
            var fds = CheckFdsUnix(); ClassifyAndLog("fds", fds);
            var workers = CountWorkers(); ClassifyAndLog("workers", workers);
        }
    }
}
