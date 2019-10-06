// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class ExternalCommandRunner
    {

        public static string RunExternalCommand(string command, params string[] args) => RunExternalCommand(command, args, true);

        public static string RunExternalCommand(string command, string[] args, bool Redirect)
        {
            string result = default(string);
            using var process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = string.Join(' ', args),
                    RedirectStandardOutput = Redirect,
                    RedirectStandardError = Redirect,
                    UseShellExecute = false,
                    CreateNoWindow = false
                }
            };
            Serilog.Log.Verbose("Running external command {0} {1}", command, Newtonsoft.Json.JsonConvert.SerializeObject(args));
            process.Start();
            if (Redirect)
            {
                result = process.StandardOutput.ReadToEnd();
            }
            process.WaitForExit();
            return result;
        }

        public static string RunExternalCommand(string filename, string arguments = null)
        {
            using var process = new Process();

            process.StartInfo.FileName = filename;
            if (!string.IsNullOrEmpty(arguments))
            {
                process.StartInfo.Arguments = arguments;
            }

            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            process.StartInfo.UseShellExecute = false;

            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.RedirectStandardOutput = true;
            var stdOutput = new StringBuilder();
            process.OutputDataReceived += (sender, args) => stdOutput.AppendLine(args.Data); // Use AppendLine rather than Append since args.Data is one line of output, not including the newline character.

            string stdError = null;
            try
            {
                process.Start();
                process.BeginOutputReadLine();
                stdError = process.StandardError.ReadToEnd();
                process.WaitForExit();
            }
            catch (Exception e)
            {
                throw new ExternalException("OS error while executing " + Format(filename, arguments) + ": " + e.Message, e);
            }

            if (process.ExitCode == 0)
            {
                return stdOutput.ToString();
            }
            else
            {
                var message = new StringBuilder();

                if (!string.IsNullOrEmpty(stdError))
                {
                    message.AppendLine(stdError);
                }

                if (stdOutput.Length != 0)
                {
                    message.AppendLine("Std output:");
                    message.AppendLine(stdOutput.ToString());
                }

                throw new ExternalException(Format(filename, arguments) + " finished with exit code = " + process.ExitCode + ": " + message);
            }
        }

        private static string Format(string filename, string arguments)
        {
            return "'" + filename +
                ((string.IsNullOrEmpty(arguments)) ? string.Empty : " " + arguments) +
                "'";
        }


    }
}