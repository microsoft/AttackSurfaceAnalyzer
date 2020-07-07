using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Medallion.Shell;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class WifiCollector : BaseCollector
    {
        public WifiCollector(CollectCommandOptions? options, Action<CollectObject>? action):base(options,action)
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

        internal void ExecuteWindows(CancellationToken token)
        {
            string tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(tempDirectory);

            using var fsm = new FileSystemMonitor(new MonitorCommandOptions() 
            { 
                FileNamesOnly = true, 
                MonitoredDirectories = tempDirectory 
            }, 
            x => ParseNetShXmlFromFile(x?.Path));

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
        }

        private void ParseNetShXmlFromFile(string? nullablePath)
        {
            if (nullablePath is string path && Path.GetExtension(nullablePath) == ".xml")
            {
                try
                {
                    XElement wifiDump = XElement.Load(path);
                    var name = wifiDump.Descendants().Where(x => x.Name.LocalName == "name").First().Value;
                    var password = wifiDump.Descendants().Where(x => x.Name.LocalName == "keyMaterial").First().Value;

                    HandleChange(new WifiObject(name) { Password = password });
                }
                catch(Exception e)
                {
                    Log.Debug("Failed to parse Wi-Fi information from xml @ {0} ({1}:{2})", path, e.GetType(), e.Message);
                }
            }
        }

        internal void ExecuteMacOs(CancellationToken token)
        {
            var result = Command.Run("networksetup", new string[] { "-listpreferredwirelessnetworks", "en0" });
            result.Wait();

            if (result.Result.Success)
            {
                var trimmedResults = result.Result.StandardOutput.Split(Environment.NewLine)[1..].Select(x => x.Trim());
                if (opts.SingleThread){
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
    }
}
