// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     Collects system event logs.
    /// </summary>
    public class EventLogCollector : BaseCollector
    {
        public EventLogCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler)
        {
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        /// <summary>
        ///     Parses /var/log/auth.log and /var/log/syslog (no way to distinguish severity)
        /// </summary>
        public void ExecuteLinux(CancellationToken cancellationToken)
        {
            Regex LogHeader = new Regex("^([A-Z][a-z][a-z][0-9:\\s]*)?[\\s].*?[\\s](.*?): (.*)", RegexOptions.Compiled);

            void HandleLinuxEvent(string entry, string path)
            {
                // New log entries start with a timestamp like so: Sep 7 02:16:16 testbed sudo:
                // pam_unix(sudo:session):session opened for user root
                if (LogHeader.IsMatch(entry))
                {
                    var obj = new EventLogObject(entry)
                    {
                        Summary = LogHeader.Matches(entry).Single().Groups[3].Captures[0].Value,
                        Source = path,
                        Process = LogHeader.Matches(entry).Single().Groups[2].Captures[0].Value,
                    };
                    if (DateTime.TryParse(LogHeader.Matches(entry).Single().Groups[1].Captures[0].Value, out DateTime Timestamp))
                    {
                        obj.Timestamp = Timestamp;
                    }
                    HandleChange(obj);
                }
            }

            void ParseLinuxLog(string path)
            {
                try
                {
                    string[] log = File.ReadAllLines(path);

                    if (opts.SingleThread)
                    {
                        foreach (var entry in log)
                        {
                            if (cancellationToken.IsCancellationRequested)
                            {
                                break;
                            }
                            HandleLinuxEvent(entry, path);
                        }
                    }
                    else
                    {
                        ParallelOptions po = new ParallelOptions() { CancellationToken = cancellationToken };
                        Parallel.ForEach(log, po, entry => HandleLinuxEvent(entry, path));
                    }
                }
                catch (Exception e) when (
                    e is ArgumentException
                    || e is ArgumentNullException
                    || e is DirectoryNotFoundException
                    || e is PathTooLongException
                    || e is FileNotFoundException
                    || e is IOException
                    || e is NotSupportedException
                    || e is System.Security.SecurityException
                    || e is UnauthorizedAccessException)
                {
                    Log.Debug("Failed to parse {0}", path);
                }
            }

            ParseLinuxLog("/var/log/auth.log");
            ParseLinuxLog("/var/log/syslog");
        }

        /// <summary>
        ///     Collect event logs on macOS using the 'log' utility
        /// </summary>
        public void ExecuteMacOs(CancellationToken cancellationToken)
        {
            // New log entries start with a timestamp like so: 2019-09-25 20:38:53.784594-0700 0xdbf47 Error
            // 0x0 0 0 kernel: (Sandbox) Sandbox: mdworker(15726) deny(1) mach-lookup com.apple.security.syspolicy
            Regex MacLogHeader = new Regex("^([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]).*?0x[0-9a-f]*[\\s]*([A-Za-z]*)[\\s]*0x[0-9a-f][\\s]*[0-9]*[\\s]*([0-9]*)[\\s]*(.*?):(.*)", RegexOptions.Compiled);
            EventLogObject? curObject = null;

            using var process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "log",
                    Arguments = opts.GatherVerboseLogs ? "show" : "show --predicate \"messageType == 16 || messageType == 17\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };

            var stdError = new StringBuilder();
            process.ErrorDataReceived += (sender, args) => stdError.AppendLine(args.Data);
            try
            {
                process.Start();
                //Throw away header
                process.StandardOutput.ReadLine();

                while (!process.StandardOutput.EndOfStream)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }
                    var evt = process.StandardOutput.ReadLine();

                    if (evt != null && MacLogHeader.IsMatch(evt))
                    {
                        if (curObject != null)
                        {
                            HandleChange(curObject);
                        }

                        curObject = new EventLogObject(evt)
                        {
                            Level = MacLogHeader.Matches(evt).Single().Groups[2].Value,
                            Summary = $"{MacLogHeader.Matches(evt).Single().Groups[4].Captures[0].Value}:{MacLogHeader.Matches(evt).Single().Groups[5].Captures[0].Value}",
                            Source = MacLogHeader.Matches(evt).Single().Groups[4].Captures[0].Value,
                        };
                        if (DateTime.TryParse(MacLogHeader.Matches(evt).Single().Groups[1].Captures[0].Value, out DateTime Timestamp))
                        {
                            curObject.Timestamp = Timestamp;
                        }
                    }
                    else
                    {
                        if (curObject != null)
                        {
                            if (evt != null)
                            {
                                if (curObject.Data == null)
                                {
                                    curObject.Data = new List<string>();
                                }
                                curObject.Data.Add(evt);
                            }
                        }
                    }
                }
                process.WaitForExit();
                if (curObject != null)
                {
                    HandleChange(curObject);
                }
            }
            catch (Exception e)
            {
                Log.Debug(e, "Failed to gather event logs on Mac OS. {0}", stdError);
            }
        }

        /// <summary>
        ///     Collect event logs on Windows using System.Diagnostics.EventLog
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Official documentation for this functionality does not specify what exceptions it throws. https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlogentrycollection?view=netcore-3.0")]
        public void ExecuteWindows(CancellationToken cancellationToken)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return;
            }
            void ParseWindowsLog(EventLogEntry entry)
            {
                if (opts.GatherVerboseLogs || entry.EntryType.ToString() == "Warning" || entry.EntryType.ToString() == "Error")
                {
                    var sentences = entry.Message.Split('.');

                    //Let's add the periods back.
                    for (var i = 0; i < sentences.Length; i++)
                    {
                        sentences[i] = string.Concat(sentences[i], ".");
                    }

                    EventLogObject obj = new EventLogObject($"{entry.TimeGenerated.ToString("o", CultureInfo.InvariantCulture)} {entry.EntryType.ToString()} {entry.Message}")
                    {
                        Level = entry.EntryType.ToString(),
                        Summary = sentences[0],
                        Source = string.IsNullOrEmpty(entry.Source) ? null : entry.Source,
                        Timestamp = entry.TimeGenerated,
                        Data = new List<string>() { entry.Message }
                    };
                    HandleChange(obj);
                }
            }
            EventLog[] logs = EventLog.GetEventLogs();
            foreach (var log in logs)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                try
                {
                    EventLogEntryCollection coll = log.Entries;

                    if (opts.SingleThread)
                    {
                        foreach (EventLogEntry? entry in coll)
                        {
                            if (cancellationToken.IsCancellationRequested)
                            {
                                break;
                            }
                            if (entry != null)
                            {
                                ParseWindowsLog(entry);
                            }
                        }
                    }
                    else
                    {
                        List<EventLogEntry> coll2 = new List<EventLogEntry>();
                        ParallelOptions po = new ParallelOptions();
                        po.CancellationToken = cancellationToken;
                        foreach (EventLogEntry? entry in coll)
                        {
                            if (entry != null)
                            {
                                coll2.Add(entry);
                            }
                        }
                        Parallel.ForEach(coll2, po, entry => ParseWindowsLog(entry));
                    }
                }
                catch (Exception e)
                {
                    Log.Debug(e, "Error parsing log {0}", log.Source);
                }
            }
        }

        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows(cancellationToken);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux(cancellationToken);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs(cancellationToken);
            }
        }
    }
}