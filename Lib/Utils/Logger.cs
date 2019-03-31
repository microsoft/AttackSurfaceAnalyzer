// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using NLog;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Logger
    {
        public static ILogger Instance { get; private set; }

        static Logger()
        {
            Instance = LogManager.GetCurrentClassLogger();
        }

        public static void Output(string message, params object[] args)
        {
            Logger.Instance.Info(message, args);
        }
        
    }
}