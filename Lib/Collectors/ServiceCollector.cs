// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
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
            System.Management.SelectQuery sQuery = new System.Management.SelectQuery("select * from Win32_Service"); // where name = '{0}'", "MCShield.exe"));
            using System.Management.ManagementObjectSearcher mgmtSearcher = new System.Management.ManagementObjectSearcher(sQuery);
            foreach (System.Management.ManagementObject service in mgmtSearcher.Get())
            {
                try
                {
                    var val = service.GetPropertyValue("Name").ToString();
                    if (val != null)
                    {
                        var obj = new ServiceObject(val);

                        val = service.GetPropertyValue("AcceptPause")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.AcceptPause = bool.Parse(val);

                        val = service.GetPropertyValue("AcceptStop")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.AcceptStop = bool.Parse(val);

                        obj.Caption = service.GetPropertyValue("Caption")?.ToString();

                        val = service.GetPropertyValue("CheckPoint")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.CheckPoint = uint.Parse(val, CultureInfo.InvariantCulture);

                        obj.CreationClassName = service.GetPropertyValue("CreationClassName")?.ToString();

                        val = service.GetPropertyValue("DelayedAutoStart")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.DelayedAutoStart = bool.Parse(val);

                        obj.Description = service.GetPropertyValue("Description")?.ToString();

                        val = service.GetPropertyValue("DesktopInteract")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.DesktopInteract = bool.Parse(val);

                        obj.DisplayName = service.GetPropertyValue("DisplayName")?.ToString();
                        obj.ErrorControl = service.GetPropertyValue("ErrorControl")?.ToString();

                        val = service.GetPropertyValue("ExitCode")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.ExitCode = uint.Parse(val, CultureInfo.InvariantCulture);

                        if (DateTime.TryParse(service.GetPropertyValue("InstallDate")?.ToString(), out DateTime dateTime)){
                            obj.InstallDate = dateTime;
                        }
                        obj.PathName = service.GetPropertyValue("PathName")?.ToString();

                        val = service.GetPropertyValue("ProcessId")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.ProcessId = uint.Parse(val, CultureInfo.InvariantCulture);

                        val = service.GetPropertyValue("ServiceSpecificExitCode")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.ServiceSpecificExitCode = uint.Parse(val, CultureInfo.InvariantCulture);

                        obj.ServiceType = service.GetPropertyValue("ServiceType")?.ToString();

                        val = service.GetPropertyValue("Started").ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.Started = bool.Parse(val);

                        obj.StartMode = service.GetPropertyValue("StartMode")?.ToString();
                        obj.StartName = service.GetPropertyValue("StartName")?.ToString();
                        obj.State = service.GetPropertyValue("State")?.ToString();
                        obj.Status = service.GetPropertyValue("Status")?.ToString();
                        obj.SystemCreationClassName = service.GetPropertyValue("SystemCreationClassName")?.ToString();
                        obj.SystemName = service.GetPropertyValue("SystemName")?.ToString();

                        val = service.GetPropertyValue("TagId")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.TagId = uint.Parse(val, CultureInfo.InvariantCulture);

                        val = service.GetPropertyValue("WaitHint")?.ToString();
                        if (!string.IsNullOrEmpty(val))
                            obj.WaitHint = uint.Parse(val, CultureInfo.InvariantCulture);

                        DatabaseManager.Write(obj, RunId);
                    }
                }
                catch (Exception e) when (
                    e is TypeInitializationException ||
                    e is PlatformNotSupportedException)
                {
                    Log.Warning(Strings.Get("CollectorNotSupportedOnPlatform"), GetType().ToString());
                }
            }

            foreach(var file in DirectoryWalker.WalkDirectory("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"))
            {
                var name = file.Split(Path.DirectorySeparatorChar)[^1];
                var fso = FileSystemCollector.FilePathToFileSystemObject(file);
                var obj = new ServiceObject(file)
                {
                    DisplayName = name,
                    Name = name,
                    PathName = file,
                    InstallDate = fso.Created
                };

                DatabaseManager.Write(obj,RunId);
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