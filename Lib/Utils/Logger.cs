// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using NLog;
using NLog.Config;
using NLog.Targets;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Logger
    {

        public static ILogger Instance { get; private set; }

        static Logger()
        {
            Instance = LogManager.GetCurrentClassLogger();
        }

        public static void Setup()
        {
            Setup(false, false);
        }

        public static void Setup(bool debug, bool verbose)
        {
            var config = new LoggingConfiguration();

            var consoleTarget = new ColoredConsoleTarget("console")
            {
                Layout = @"${date:format=HH\:mm\:ss} ${level} ${message} ${exception}"
            };
            config.AddTarget(consoleTarget);

            var fileTarget = new FileTarget("debug")
            {
                FileName = "asa.debug.log",
                Layout = "${longdate} ${level} ${message}  ${exception}"
            };
            config.AddTarget(fileTarget);

            if (debug || verbose)
            {
                config.AddRuleForOneLevel(LogLevel.Debug, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Warn, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Error, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Fatal, consoleTarget);
            }
            if (debug || verbose)
            {
                config.AddRuleForAllLevels(fileTarget);
            }
            //if (trace)
            //{
            //    config.AddRuleForAllLevels(fileTarget);
            //    config.AddRuleForAllLevels(consoleTarget);
            //}
            else
            {
                config.AddRuleForOneLevel(LogLevel.Info, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Warn, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Error, consoleTarget);
                config.AddRuleForOneLevel(LogLevel.Fatal, consoleTarget);
            }

            LogManager.Configuration = config;
        }
    }
}