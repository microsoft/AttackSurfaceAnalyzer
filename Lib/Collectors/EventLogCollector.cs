// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Linq;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System.Diagnostics.Tracing;
using System.IO;
using System.Diagnostics;
using System;
using System.Globalization;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects system event logs.
    /// </summary>
    public class EventLogCollector : BaseCollector
    {
        private bool GatherVerboseLogs;
        public EventLogCollector(string runId, bool GatherVerboseLogs = false)
        {
            this.RunId = runId;
            this.GatherVerboseLogs = GatherVerboseLogs;
        }

        public override void ExecuteInternal()
        {
            if (!CanRunOnPlatform())
            {
                return;
            }

            _ = DatabaseManager.Transaction;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs();
            }

            DatabaseManager.Commit();
        }

        /// <summary>
        /// Collect event logs on Windows using System.Diagnostics.EventLog
        /// </summary>
        public void ExecuteWindows()
        {
            EventLog[] logs = EventLog.GetEventLogs();
            foreach (var log in logs)
            {
                try
                {
                    EventLogEntryCollection coll = log.Entries;

                    foreach (EventLogEntry entry in coll)
                    {
                        if (GatherVerboseLogs || entry.EntryType.ToString() == "Warning" || entry.EntryType.ToString() == "Error")
                        {
                            var sentences = entry.Message.Split('.');

                            //Let's add the periods back.
                            for (var i = 0; i<sentences.Length; i++)
                            {
                                sentences[i] = string.Concat(sentences[i],".");
                            }

                            EventLogObject obj = new EventLogObject()
                            {
                                Level = entry.EntryType.ToString(),
                                Summary = sentences[0],
                                Source = string.IsNullOrEmpty(entry.Source) ? null : entry.Source,
                                Timestamp = entry.TimeGenerated.ToString("o", CultureInfo.InvariantCulture),
                                Event = $"{entry.TimeGenerated.ToString("o", CultureInfo.InvariantCulture)} {entry.EntryType.ToString()} {entry.Message}"
                            };
                            obj.Data.Add(entry.Message);
                            DatabaseManager.Write(obj, RunId);
                        }
                    }
                }
                catch(Exception e)
                {
                    Log.Debug(e, "Error parsing log {0}", log.Source);
                }
            }
        }

        /// <summary>
        /// Parses /var/log/auth.log and /var/log/syslog (no way to distinguish severity)
        /// </summary>
        public void ExecuteLinux()
        {
            try
            {
                Regex LogHeader = new Regex("^([A-Z][a-z][a-z][0-9:\\s]*)?[\\s].*?[\\s](.*?): (.*)");
                string[] authLog = File.ReadAllLines("/var/log/auth.log");
                foreach (var entry in authLog)
                {
                    // New log entries start with a timestamp like so:
                    // Sep  7 02:16:16 testbed sudo: pam_unix(sudo:session):session opened for user root
                    if (LogHeader.IsMatch(entry))
                    {
                        var obj = new EventLogObject()
                        {
                            Event = entry,
                            Summary = LogHeader.Matches(entry).Single().Groups[3].Captures[0].Value,
                            Timestamp = LogHeader.Matches(entry).Single().Groups[1].Captures[0].Value,
                            Source = "/var/log/auth.log",
                            Process = LogHeader.Matches(entry).Single().Groups[2].Captures[0].Value,
                        };
                        DatabaseManager.Write(obj, RunId);
                    }
                    // New log entries start with a timestamp like so:
                    // Sep  7 02:16:16 testbed systemd[1]: Reloading
                }

                string[] sysLog = File.ReadAllLines("/var/log/syslog");
                foreach (var entry in sysLog)
                {
                    // New log entries start with a timestamp like so:
                    // Sep  7 02:16:16 testbed systemd[1]: Reloading
                    if (LogHeader.IsMatch(entry))
                    {
                        var obj = new EventLogObject()
                        {
                            Event = entry,
                            Summary = LogHeader.Matches(entry).Single().Groups[2].Captures[0].Value,
                            Timestamp = LogHeader.Matches(entry).Single().Groups[0].Captures[0].Value,
                            Source = "/var/log/syslog",
                            Process = LogHeader.Matches(entry).Single().Groups[1].Captures[0].Value,
                        };
                        DatabaseManager.Write(obj, RunId);
                    }
                }
            }
            catch(Exception e)
            {
                Log.Debug(e, "Failed to parse /var/log/auth.log");
            }

        }

        /// <summary>
        /// Collect event logs on macOS using the 'log' utility
        /// </summary>
        public void ExecuteMacOs()
        {
            _ = DatabaseManager.Transaction;

            var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "events");
            var file = (GatherVerboseLogs)? ExternalCommandRunner.RunExternalCommand("log", "show") : ExternalCommandRunner.RunExternalCommand("log", "show --predicate \"messageType == 16 || messageType == 17\"");

            // New log entries start with a timestamp like so:
            // 2019-09-25 20:38:53.784594-0700 0xdbf47    Error       0x0                  0      0    kernel: (Sandbox) Sandbox: mdworker(15726) deny(1) mach-lookup com.apple.security.syspolicy
            Regex LogHeader = new Regex("^([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]).*?0x[0-9a-f]*[\\s]*([A-Za-z]*)[\\s]*0x[0-9a-f][\\s]*[0-9]*[\\s]*([0-9]*)[\\s]*(.*?):(.*)");

            
            List<string> data = null;
            string previousLine = null;
            foreach(var line in file.Split('\n'))
            {
                if (LogHeader.IsMatch(line))
                {
                    if (previousLine != null)
                    {
                        var obj = new EventLogObject()
                        {
                            Event = previousLine,
                            Level = LogHeader.Matches(previousLine).Single().Groups[2].Value,
                            Summary = $"{LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value}:{LogHeader.Matches(previousLine).Single().Groups[5].Captures[0].Value}",
                            Timestamp = LogHeader.Matches(previousLine).Single().Groups[1].Captures[0].Value,
                            Source = LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value
                        };
                        if (data.Count > 0)
                        {
                            obj.Data.AddRange(data);
                        }

                        DatabaseManager.Write(obj, RunId);
                    }
                    previousLine = line;
                    data = new List<string>();
                }
                else
                {
                    if (previousLine != null)
                    {
                        data.Add(line);
                    }
                }
            }
            if (previousLine != null)
            {
                var obj = new EventLogObject()
                {
                    Event = previousLine,
                    Level = LogHeader.Matches(previousLine).Single().Groups[2].Value,
                    Summary = $"{LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value}:{LogHeader.Matches(previousLine).Single().Groups[5].Captures[0].Value}",
                    Timestamp = LogHeader.Matches(previousLine).Single().Groups[1].Captures[0].Value,
                    Source = LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value
                };
                if (data.Count > 0)
                {
                    obj.Data.AddRange(data);
                }
                DatabaseManager.Write(obj, RunId);
            }
            DatabaseManager.Commit();
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }
    }
}