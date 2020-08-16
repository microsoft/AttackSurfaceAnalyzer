using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Medallion.Shell;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    public class WifiCollector : BaseCollector
    {
        public WifiCollector(CollectorOptions? options = null, Action<CollectObject>? action = null) : base(options, action)
        {
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        internal override void ExecuteInternal(CancellationToken token)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs(token);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows(token);
            }
        }

        internal void ExecuteMacOs(CancellationToken token)
        {
            var result = Command.Run("networksetup", new string[] { "-listpreferredwirelessnetworks", "en0" });
            result.Wait();

            if (result.Result.Success)
            {
                var trimmedResults = result.Result.StandardOutput.Split(Environment.NewLine)[1..].Select(x => x.Trim());
                if (opts.SingleThread)
                {
                    foreach (var line in trimmedResults)
                    {
                        if (token.IsCancellationRequested)
                        {
                            return;
                        }
                        HandleChange(MacSSIDToWifiObject(line));
                    }
                }
                else
                {
                    Parallel.ForEach(trimmedResults, new ParallelOptions() { CancellationToken = token }, line =>
                    {
                        HandleChange(MacSSIDToWifiObject(line));
                    });
                }
            }
        }

        internal void ExecuteWindows(CancellationToken token)
        {
            string tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(tempDirectory);

            var monitoredFiles = new List<string>();

            using var fsm = new FileSystemMonitor(new MonitorCommandOptions()
            {
                FileNamesOnly = true,
                MonitoredDirectories = new List<string>(){ tempDirectory }
            },
            x =>
            {
                if (x != null) { monitoredFiles.Add(x.Path); }
            });

            fsm.StartRun();

            if (opts.GatherWifiPasswords)
            {
                var result = Command.Run("netsh", new string[] { "wlan", "export", "profile", $"folder=\"{tempDirectory}\"", "key=clear" });
                result.Wait();
            }
            else
            {
                var result = Command.Run("netsh", new string[] { "wlan", "export", "profile", $"folder=\"{tempDirectory}\"" });
                result.Wait();
            }

            fsm.StopRun();

            var distinctXmlFiles = monitoredFiles.Distinct().Where(x => Path.GetExtension(x) == ".xml");

            if (opts.SingleThread)
            {
                foreach (var xmlFile in distinctXmlFiles)
                {
                    if (token.IsCancellationRequested)
                    {
                        return;
                    }
                    ParseNetShXmlFromFile(xmlFile);
                }
            }
            else
            {
                Parallel.ForEach(distinctXmlFiles, new ParallelOptions() { CancellationToken = token }, xmlFile =>
                {
                    ParseNetShXmlFromFile(xmlFile);
                });
            }
        }

        internal WifiObject MacSSIDToWifiObject(string SSID)
        {
            var obj = new WifiObject(SSID);

            if (opts.GatherWifiPasswords && AsaHelpers.IsAdmin())
            {
                var result = Command.Run("security", new string[] { "find-generic-password", "-ga", "\"{SSID}\"" });
                if (result.Result.Success)
                {
                    var passwordLine = result.Result.StandardOutput.Split(Environment.NewLine).Where(x => x.StartsWith("password:"));
                    if (passwordLine.Any())
                    {
                        obj.Password = passwordLine.First().Split(':')[1];
                    }
                }
                else
                {
                    Log.Debug("Failed to get password for {0}.", SSID);
                }
            }

            return obj;
        }

        private void ParseNetShXmlFromFile(string path)
        {
            if (Path.GetExtension(path) == ".xml")
            {
                try
                {
                    XElement wifiDump = XElement.Load(path);
                    var name = wifiDump.Descendants().Where(x => x.Name.LocalName == "name").FirstOrDefault().Value;

                    if (name != null)
                    {
                        HandleChange(new WifiObject(name)
                        {
                            Password = wifiDump.Descendants().Where(x => x.Name.LocalName == "keyMaterial").FirstOrDefault()?.Value,
                            Authentication = wifiDump.Descendants().Where(x => x.Name.LocalName == "authentication").FirstOrDefault().Value,
                            Encryption = wifiDump.Descendants().Where(x => x.Name.LocalName == "encryption").FirstOrDefault().Value
                        });
                    }
                }
                catch (Exception e)
                {
                    Log.Debug("Failed to parse Wi-Fi information from xml @ {0} ({1}:{2})", path, e.GetType(), e.Message);
                }
            }
        }
    }
}