using AttackSurfaceAnalyzer.Utils;
using System;
using System.Runtime.InteropServices;
using Serilog;

namespace AttackSurfaceAnalyzer
{
    class AsaDemoGenerator
    {
        public static void Main(string[] args)
        {
            Logger.Setup(true,true);

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (!Elevation.IsAdministrator())
                    {
                        Log.Fatal("Must run as administrator.");
                        Log.CloseAndFlush();
                        Environment.Exit(-1);
                    }
                    var user = System.Guid.NewGuid().ToString().Substring(0,10);
                    var password = System.Guid.NewGuid().ToString().Substring(0,10);
                    var cmd = string.Format("user /add {0} {1}", user, password);
                    ExternalCommandRunner.RunExternalCommand("net",cmd);

                    Log.Information("Created user {0} with password {1}", user, password);

                    var serviceName = System.Guid.NewGuid();
                    var exeName = "AsaDemoService.exe";

                    cmd = string.Format("create {0} binPath=\"{1}\"", serviceName, exeName);
                    ExternalCommandRunner.RunExternalCommand("sc.exe",cmd);

                    Log.Information("Created service {0} for not-present exe {1}", serviceName, exeName);
                }
                else
                {
                    Log.Fatal("Only supported on Windows.");
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadLine();

            }

        }
    }
}
