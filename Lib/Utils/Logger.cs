using System;
using NLog;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Logger
    {
        public static ILogger Instance { get; private set; }

        static Logger()
        {
            var config = new NLog.Config.LoggingConfiguration();

            var logfile = new NLog.Targets.FileTarget("logfile") { FileName = "asa.debug.txt" };
            var logconsole = new NLog.Targets.ConsoleTarget("logconsole");

            config.AddRule(LogLevel.Info, LogLevel.Fatal, logconsole);
            config.AddRule(LogLevel.Debug, LogLevel.Fatal, logfile);

            NLog.LogManager.Configuration = config;

            Instance = LogManager.GetCurrentClassLogger();
        }

        public static void Output(string message, params object[] args)
        {
            Logger.Instance.Info(message, args);
        }
        
    }
}