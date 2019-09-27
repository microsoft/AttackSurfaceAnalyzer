﻿// Copyright (c) Microsoft Corporation. All rights reserved.
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

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects system event logs.
    /// </summary>
    public class EventLogCollector : BaseCollector
    {
        public EventLogCollector(string runId)
        {
            this.runId = runId;
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
                        if (entry.EntryType.ToString() == "Warning" || entry.EntryType.ToString() == "Error")
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
                                Source = string.IsNullOrEmpty(entry.Source) ? null:entry.Source,
                                Data = new List<string>() { entry.Message },
                                Timestamp = entry.TimeGenerated.ToString(),
                                Event = string.Format("{0} {1} {2}", entry.TimeGenerated.ToString(), entry.EntryType.ToString(), entry.Message)
                            };
                            DatabaseManager.Write(obj, runId);
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
        /// Parse /var/log
        /// </summary>
        public void ExecuteLinux()
        {

        }

        /// <summary>
        /// Collect event logs on macOS using the 'log' utility.
        /// </summary>
        public void ExecuteMacOs()
        {
            _ = DatabaseManager.Transaction;

            var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "events");
            //var file = ExternalCommandRunner.RunExternalCommand("sh", "-c 'log show --predicate \"messageType == 16 || messageType == 17\" --last 10m > logEntries'");
            var file = ExternalCommandRunner.RunExternalCommand("log", "show --predicate \"messageType == 16 || messageType == 17\"");



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
                            Data = data,
                            Event = previousLine,
                            Level = LogHeader.Matches(previousLine).Single().Groups[2].Value,
                            Summary = string.Format("{0}:{1}", LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value, Timestamp.Matches(previousLine).Single().Groups[5].Captures[0].Value),
                            Timestamp = LogHeader.Matches(previousLine).Single().Groups[1].Captures[0].Value,
                            Source = LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value
                        };
                        DatabaseManager.Write(obj, runId);
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
                    Data = data,
                    Event = previousLine,
                    Timestamp = Timestamp.Matches(previousLine).Single().Groups[0].Captures[0].Value
                };
                DatabaseManager.Write(obj, runId);
            }
            DatabaseManager.Commit();
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }
    }
}