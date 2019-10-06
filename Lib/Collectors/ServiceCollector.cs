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
using System.Threading;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects metadata about services registered on the system.
    /// </summary>
    public class ServiceCollector : BaseCollector
    {
        public ServiceCollector(string runId)
        {
            this.RunId = runId;
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
            using (System.Management.ManagementObjectSearcher mgmtSearcher = new System.Management.ManagementObjectSearcher(sQuery))
            {
                foreach (System.Management.ManagementObject service in mgmtSearcher.Get())
                {
                    var obj = new ServiceObject();

                    if (service["AcceptPause"] != null)
                        obj.AcceptPause = bool.Parse(service["AcceptPause"].ToString());
                    if (service["AcceptStop"] != null)
                        obj.AcceptStop = bool.Parse(service["AcceptStop"].ToString());
                    if (service["Caption"] != null)
                        obj.Caption = service["Caption"].ToString();
                    if (service["CheckPoint"] != null)
                        obj.CheckPoint = uint.Parse(service["CheckPoint"].ToString(), CultureInfo.InvariantCulture);
                    if (service["CreationClassName"] != null)
                        obj.CreationClassName = service["CreationClassName"].ToString();
                    if (service["DelayedAutoStart"] != null)
                        obj.DelayedAutoStart = bool.Parse(service["DelayedAutoStart"].ToString());
                    if (service["Description"] != null)
                        obj.Description = service["Description"].ToString();
                    if (service["DesktopInteract"] != null)
                        obj.DesktopInteract = bool.Parse(service["DesktopInteract"].ToString());
                    if (service["DisplayName"] != null)
                        obj.DisplayName = service["DisplayName"].ToString();
                    if (service["ErrorControl"] != null)
                        obj.ErrorControl = service["ErrorControl"].ToString();
                    if (service["ExitCode"] != null)
                        obj.ExitCode = uint.Parse(service["ExitCode"].ToString(), CultureInfo.InvariantCulture);
                    if (service["InstallDate"] != null)
                        obj.InstallDate = service["InstallDate"].ToString();
                    if (service["Name"] != null)
                        obj.Name = service["Name"].ToString();
                    if (service["PathName"] != null)
                        obj.PathName = service["PathName"].ToString();
                    if (service["ProcessId"] != null)
                        obj.ProcessId = uint.Parse(service["ProcessId"].ToString(), CultureInfo.InvariantCulture);
                    if (service["ServiceSpecificExitCode"] != null)
                        obj.ServiceSpecificExitCode = uint.Parse(service["ServiceSpecificExitCode"].ToString(), CultureInfo.InvariantCulture);
                    if (service["ServiceType"] != null)
                        obj.ServiceType = service["ServiceType"].ToString();
                    if (service["Started"] != null)
                        obj.Started = bool.Parse(service["Started"].ToString());
                    if (service["StartMode"] != null)
                        obj.StartMode = service["StartMode"].ToString();
                    if (service["StartName"] != null)
                        obj.StartName = service["StartName"].ToString();
                    if (service["State"] != null)
                        obj.State = service["State"].ToString();
                    if (service["Status"] != null)
                        obj.Status = service["Status"].ToString();
                    if (service["SystemCreationClassName"] != null)
                        obj.SystemCreationClassName = service["SystemCreationClassName"].ToString();
                    if (service["SystemName"] != null)
                        obj.SystemName = service["SystemName"].ToString();
                    if (service["TagId"] != null)
                        obj.TagId = uint.Parse(service["TagId"].ToString(), CultureInfo.InvariantCulture);
                    if (service["WaitHint"] != null)
                        obj.WaitHint = uint.Parse(service["WaitHint"].ToString(), CultureInfo.InvariantCulture);

                    DatabaseManager.Write(obj, this.RunId);
                }
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
                        var obj = new ServiceObject()
                        {
                            DisplayName = _fields[4],
                            Name = _fields[0],
                            State = _fields[3],
                        };

                        DatabaseManager.Write(obj, this.RunId);
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

                    var obj = new ServiceObject()
                    {
                        DisplayName = serviceName,
                        Name = serviceName,
                    };

                    DatabaseManager.Write(obj, this.RunId);
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
                    var obj = new ServiceObject()
                    {
                        DisplayName = _fields[2],
                        Name = _fields[2],
                        // If we have a current PID then it is running.
                        State = (_fields[0].Equals("-")) ? "Stopped" : "Running"
                    };
                    if (!outDict.ContainsKey(obj.Identity))
                    {
                        DatabaseManager.Write(obj, this.RunId);
                        outDict.Add(obj.Identity, obj);
                    }
                }
            }
            catch (ExternalException)
            {
                Log.Error("Error executing {0}", "launchctl list");
            }
            try { 
                // Then get the system processes
                var result = ExternalCommandRunner.RunExternalCommand("sudo", "launchctl list");

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
                        Name = _fields[2],
                        // If we have a current PID then it is running.
                        State = (_fields[0].Equals("-")) ? "Stopped" : "Running"
                    };

                    if (!outDict.ContainsKey(obj.Identity))
                    {
                        DatabaseManager.Write(obj, this.RunId);
                        outDict.Add(obj.Identity, obj);
                    }
                }
            }
            catch (ExternalException)
            {
                Log.Error("Error executing {0}", "sudo launchctl list");
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