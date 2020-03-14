// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects metadata about services registered on the system.
    /// </summary>
    public class ServiceCollector : BaseCollector
    {
        public ServiceCollector(string runId)
        {
            RunId = runId;
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
        /// Uses ServiceController.
        /// </summary>
        public void ExecuteWindows()
        {
            try
            {
                System.Management.SelectQuery sQuery = new System.Management.SelectQuery("select * from Win32_Service"); // where name = '{0}'", "MCShield.exe"));
                using (System.Management.ManagementObjectSearcher mgmtSearcher = new System.Management.ManagementObjectSearcher(sQuery))
                {
                    foreach (System.Management.ManagementObject service in mgmtSearcher.Get())
                    {
                        var val = service["Name"].ToString();
                        if (val != null)
                        {
                            var obj = new ServiceObject(val);

                            val = service["AcceptPause"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.AcceptPause = bool.Parse(val);

                            val = service["AcceptStop"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.AcceptStop = bool.Parse(val);

                            val = service["Caption"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.Caption = val;

                            val = service["CheckPoint"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.CheckPoint = uint.Parse(val, CultureInfo.InvariantCulture);

                            val = service["CreationClassName"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.CreationClassName = val;

                            val = service["DelayedAutoStart"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.DelayedAutoStart = bool.Parse(val);

                            val = service["Description"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.Description = val;

                            val = service["DesktopInteract"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.DesktopInteract = bool.Parse(val);

                            val = service["DisplayName"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.DisplayName = val;

                            service["ErrorControl"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.ErrorControl = val;

                            val = service["ExitCode"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.ExitCode = uint.Parse(val, CultureInfo.InvariantCulture);

                            val = service["InstallDate"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.InstallDate = val;

                            val = service["PathName"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.PathName = val;

                            val = service["ProcessId"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.ProcessId = uint.Parse(val, CultureInfo.InvariantCulture);

                            val = service["ServiceSpecificExitCode"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.ServiceSpecificExitCode = uint.Parse(val, CultureInfo.InvariantCulture);

                            obj.ServiceType = service["ServiceType"].ToString();

                            val = service["Started"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.Started = bool.Parse(val);

                            obj.StartMode = service["StartMode"].ToString();

                            obj.StartName = service["StartName"].ToString();

                            obj.State = service["State"].ToString();
                            obj.Status = service["Status"].ToString();
                            obj.SystemCreationClassName = service["SystemCreationClassName"].ToString();
                            obj.SystemName = service["SystemName"].ToString();

                            val = service["TagId"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.TagId = uint.Parse(val, CultureInfo.InvariantCulture);

                            val = service["WaitHint"].ToString();
                            if (!string.IsNullOrEmpty(val))
                                obj.WaitHint = uint.Parse(val, CultureInfo.InvariantCulture);

                            DatabaseManager.Write(obj, RunId);
                        }
                    }
                }
            }
            catch (Exception e) when (
                e is TypeInitializationException ||
                e is PlatformNotSupportedException)
            {
                Log.Warning(Strings.Get("CollectorNotSupportedOnPlatform"), GetType().ToString());
            }
        }

        /// <summary>
        /// Uses systemctl (relies on systemd) and also checks /etc/init.d
        /// </summary>
        public void ExecuteLinux()
        {
            try
            {
                var result = ExternalCommandRunner.RunExternalCommand("systemctl", "list-units --type service");

                //Split lines and remove header
                var lines = result.Split('\n').Skip(1);

                foreach (var _line in lines)
                {
                    var _fields = _line.Split('\t');

                    if (_fields.Length == 5)
                    {
                        var obj = new ServiceObject(_fields[0])
                        {
                            DisplayName = _fields[4],
                            State = _fields[3],
                        };

                        DatabaseManager.Write(obj, RunId);
                    }
                }
            }
            catch (ExternalException)
            {
                Log.Error("Error executing {0}", "systemctl list-units --type service");
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

                    var obj = new ServiceObject(serviceName)
                    {
                        DisplayName = serviceName,
                    };

                    DatabaseManager.Write(obj, RunId);
                }
            }
            catch (ExternalException)
            {
                Log.Error("Error executing {0}", "ls /etc/init.d/ -l");
            }


            // CentOS
            // chkconfig --list

            // BSD
            // service -l
            // this provides very minor amount of info
        }

        /// <summary>
        /// Uses launchctl
        /// </summary>
        public void ExecuteMacOs()
        {
            // Get the user processes
            // run "launchtl dumpstate" for the super detailed view
            // However, dumpstate is difficult to parse
            Dictionary<string, ServiceObject> outDict = new Dictionary<string, ServiceObject>();
            try
            {
                var result = ExternalCommandRunner.RunExternalCommand("launchctl", "list");
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
                    var obj = new ServiceObject(_fields[2])
                    {
                        DisplayName = _fields[2],
                        // If we have a current PID then it is running.
                        State = (_fields[0].Equals("-")) ? "Stopped" : "Running"
                    };
                    if (!outDict.ContainsKey(obj.Identity))
                    {
                        DatabaseManager.Write(obj, RunId);
                        outDict.Add(obj.Identity, obj);
                    }
                }
            }
            catch (ExternalException)
            {
                Log.Error("Error executing {0}", "launchctl list");
            }
        }

        /// <summary>
        /// Executes the ServiceCollector.
        /// </summary>
        public override void ExecuteInternal()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux();
            }
        }
    }
}