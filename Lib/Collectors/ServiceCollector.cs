// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects metadata from the local file system.
    /// </summary>
    public class ServiceCollector : BaseCollector
    {
        /// <summary>
        /// A filter supplied to this function. All files must pass this filter in order to be included.
        /// </summary>

        //private static readonly string CREATE_SQL = "create table if not exists win_system_service (run_id text, row_key text, service_name text, display_name text, start_type text, current_state text)";

        public ServiceCollector(string runId)
        {
            this.runId = runId;
        }

        /// <summary>
        /// Determines whether the ServiceCollector can run or not.
        /// </summary>
        /// <returns>True on Windows, Linux, Mac OS</returns>
        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        /// <summary>
        /// Executes the ServiceCollector (main entrypoint).
        /// </summary>
        public override void Execute()
        {
            if (!this.CanRunOnPlatform())
            {
                Log.Information(Strings.Get("Err_ServiceCollectorIncompat"));
                return;
            }
            Start();
            _ = DatabaseManager.Transaction;


            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // This gathers official "services" on Windows, but perhaps neglects other startup items
                foreach (ServiceController service in ServiceController.GetServices())
                {
                    var obj = new ServiceObject()
                    {
                        DisplayName = service.DisplayName,
                        ServiceName = service.ServiceName,
                        StartType = service.StartType.ToString(),
                        CurrentState = service.Status.ToString()
                    };

                    DatabaseManager.Write(obj, this.runId);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {


                // Get the user processes
                // run "launchtl dumpstate" for the super detailed view
                // However, dumpstate is difficult to parse
                try
                {
                    var result = ExternalCommandRunner.RunExternalCommand("launchctl", "list");
                    Dictionary<string, ServiceObject> outDict = new Dictionary<string, ServiceObject>();
                    foreach (var _line in result.Split('\n'))
                    {
                        // Lines are formatted like this:
                        // PID   Exit  Name
                        //1015    0   com.apple.appstoreagent
                        var _fields = _line.Split('\t');
                        if (_fields.Length < 3 || _fields[0].Contains("PID"))
                        {
                            continue;

                        }
                        var obj = new ServiceObject()
                        {
                            DisplayName = _fields[2],
                            ServiceName = _fields[2],
                            StartType = "Unknown",
                            // If we have a current PID then it is running.
                            CurrentState = (_fields[0].Equals("-")) ? "Stopped" : "Running"
                        };
                        if (!outDict.ContainsKey(obj.Identity))
                        {
                            DatabaseManager.Write(obj, this.runId);
                            outDict.Add(obj.Identity, obj);
                        }
                    }

                    // Then get the system processes

                    result = ExternalCommandRunner.RunExternalCommand("sudo", "launchctl list");

                    foreach (var _line in result.Split('\n'))
                    {
                        // Lines are formatted like this, with single tab separation:
                        //  PID     Exit    Name
                        //  1015    0       com.apple.appstoreagent
                        var _fields = _line.Split('\t');
                        if (_fields.Length < 3 || _fields[0].Contains("PID"))
                        {
                            continue;

                        }
                        var obj = new ServiceObject()
                        {
                            DisplayName = _fields[2],
                            ServiceName = _fields[2],
                            StartType = "Unknown",
                            // If we have a current PID then it is running.
                            CurrentState = (_fields[0].Equals("-")) ? "Stopped" : "Running"
                        };

                        if (!outDict.ContainsKey(obj.Identity))
                        {
                            DatabaseManager.Write(obj, this.runId);
                            outDict.Add(obj.Identity, obj);
                        }
                    }
                }
                catch (Exception e)
                {
                    Logger.DebugException(e);
                }

            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {

                try
                {
                    var result = ExternalCommandRunner.RunExternalCommand("systemctl", "list-units --type service");

                    //Split lines and remove header
                    var lines = result.Split('\n').Skip(1);

                    foreach (var _line in lines)
                    {
                        var _fields = _line.Split('\t');

                        if (_fields.Count() == 5)
                        {
                            var obj = new ServiceObject()
                            {
                                DisplayName = _fields[4],
                                ServiceName = _fields[0],
                                StartType = "Unknown",
                                CurrentState = _fields[3],
                            };

                            DatabaseManager.Write(obj, this.runId);
                        }
                    }
                }
                catch (Exception e)
                {
                    Logger.DebugException(e);
                }

                try
                {
                    var result = ExternalCommandRunner.RunExternalCommand("ls", "/etc/init.d/ -l");

                    var lines = result.Split('\n').Skip(1);
                    String pattern = @".*\s(.*)";

                    foreach (var _line in lines)
                    {
                        Match match = Regex.Match(_line, pattern);
                        GroupCollection groups = match.Groups;
                        var serviceName = groups[1].ToString();

                        var obj = new ServiceObject()
                        {
                            DisplayName = serviceName,
                            ServiceName = serviceName,
                            StartType = "Unknown",
                            CurrentState = "Unknown"
                        };

                        DatabaseManager.Write(obj, this.runId);
                    }
                }
                catch (Exception e)
                {
                    Logger.DebugException(e);
                }


                // CentOS
                // chkconfig --list

                // BSD
                // service -l
                // this provides very minor amount of info
            }
            DatabaseManager.Commit();
            Stop();
        }

        private string underscoreToCamelCase(string name)
        {
            if (string.IsNullOrEmpty(name) || !name.Contains("_"))
            {
                return name;
            }
            string[] array = name.Split('_');
            for (int i = 0; i < array.Length; i++)
            {
                string s = array[i];
                string first = string.Empty;
                string rest = string.Empty;
                if (s.Length > 0)
                {
                    first = Char.ToUpperInvariant(s[0]).ToString();
                }
                if (s.Length > 1)
                {
                    rest = s.Substring(1).ToLowerInvariant();
                }
                array[i] = first + rest;
            }
            string newname = string.Join("", array);
            if (newname.Length > 0)
            {
                newname = Char.ToUpperInvariant(newname[0]) + newname.Substring(1);
            }
            else
            {
                newname = name;
            }
            return newname;
        }
    }
}