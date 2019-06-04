// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Diagnostics;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class ExternalCommandRunner
    {

        public static string RunExternalCommand(string command, params string[] args)
        {
            var process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = string.Join(' ', args),
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            string result = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return result;
        }
    }
}