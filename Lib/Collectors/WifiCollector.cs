using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
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
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        internal override void ExecuteInternal(CancellationToken token)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs(token);
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
