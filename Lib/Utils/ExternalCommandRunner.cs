// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public static class ExternalCommandRunner
    {
        public static int RunExternalCommand(string command, string arguments, out string StdOut, out string StdErr)
        {
            using var process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = string.IsNullOrEmpty(arguments) ? string.Empty : arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };

            try
            {
                process.Start();
                process.WaitForExit();
            }
            catch (Exception e)
            {
                throw new ExternalException("OS error while executing " + Format(command, arguments) + ": " + e.Message, e);
            }

            StdOut = process.StandardOutput.ReadToEnd();
            StdErr = process.StandardError.ReadToEnd();

            return process.ExitCode;
        }

        public static string RunExternalCommand(string filename, string arguments = "", bool Redirect = true)
        {
            using var process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = filename,
                    Arguments = string.IsNullOrEmpty(arguments) ? string.Empty : arguments,
                    RedirectStandardOutput = Redirect,
                    RedirectStandardError = Redirect,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };

            var stdOutput = new StringBuilder();
            process.OutputDataReceived += (sender, args) => stdOutput.AppendLine(args.Data); // Use AppendLine rather than Append since args.Data is one line of output, not including the newline character.

            string stdError = string.Empty;
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