// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects metadata about services registered on the system.
    /// </summary>
    public class ServiceCollector : BaseCollector
    {
        #region Public Constructors

        public ServiceCollector(CollectCommandOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler)
        {
        }

        #endregion Public Constructors

        #region Public Methods

        /// <summary>
        /// Determines whether the ServiceCollector can run or not.
        /// </summary>
        /// <returns>True on Windows, Linux, Mac OS</returns>
        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        #endregion Public Methods

        #region Internal Methods

        /// <summary>
        /// Executes the ServiceCollector.
        /// </summary>
        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows(cancellationToken);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs(cancellationToken);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux(cancellationToken);
            }
        }

        /// <summary>
        /// Uses systemctl (relies on systemd) and also checks /etc/init.d
        /// </summary>
        internal void ExecuteLinux(CancellationToken cancellationToken)
        {
            try
            {
                var result = ExternalCommandRunner.RunExternalCommand("systemctl", "list-units --type service");

                //Split lines and remove header
                var lines = result.Split('\n').Skip(1);

                foreach (var _line in lines)
                {
                    if (cancellationToken.IsCancellationRequested) { return; }

                    var _fields = _line.Split('\t');

                    if (_fields.Length == 5)
                    {
                        var obj = new ServiceObject(_fields[0])
                        {
                            DisplayName = _fields[4],
                            State = _fields[3],
                        };

                        HandleChange(obj);
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

                    HandleChange(obj);
                }
            }
            catch (ExternalException)
            {
                Log.Error("Error executing {0}", "ls /etc/init.d/ -l");
            }
            // CentOS chkconfig --list

            // BSD service -l this provides very minor amount of info
        }

        /// <summary>
        /// Uses launchctl
        /// </summary>
        internal void ExecuteMacOs(CancellationToken cancellationToken)
        {
            // Get the user processes run "launchtl dumpstate" for the super detailed view However,
            // dumpstate is difficult to parse
            Dictionary<string, ServiceObject> outDict = new Dictionary<string, ServiceObject>();
            try
            {
                var result = ExternalCommandRunner.RunExternalCommand("launchctl", "list");
                foreach (var _line in result.Split('\n'))
                {
                    if (cancellationToken.IsCancellationRequested) { return; }

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
                        HandleChange(obj);
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
        /// Uses ServiceController.
        /// </summary>
        internal void ExecuteWindows(CancellationToken cancellationToken)
        {
            try
            {
                SelectQuery sQuery = new SelectQuery("select * from Win32_Service"); // where name = '{0}'", "MCShield.exe"));
                using ManagementObjectSearcher mgmtSearcher = new ManagementObjectSearcher(sQuery);

                if (opts.SingleThread)
                {
                    foreach (ManagementObject service in mgmtSearcher.Get())
                    {
                        if (cancellationToken.IsCancellationRequested) { return; }

                        ProcessManagementObject(service);
                    }
                }
                else
                {
                    var list = new List<ManagementObject>();

                    foreach (ManagementObject service in mgmtSearcher.Get())
                    {
                        list.Add(service);
                    }
                    ParallelOptions po = new ParallelOptions() { CancellationToken = cancellationToken };
                    Parallel.ForEach(list, po, x => ProcessManagementObject(x));
                }
            }
            catch (Exception e)
            {
                Log.Warning(e, "Failed to run Service Collector.");
            }

            var fsc = new FileSystemCollector(new CollectCommandOptions() { SingleThread = opts.SingleThread });

            foreach (var file in Directory.EnumerateFiles("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"))
            {
                var name = file.Split(Path.DirectorySeparatorChar)[^1];
                var fso = fsc.FilePathToFileSystemObject(file);
                var obj = new ServiceObject(file)
                {
                    DisplayName = name,
                    Name = name,
                    PathName = file,
                    InstallDate = fso.Created
                };

                HandleChange(obj);
            }
        }

        #endregion Internal Methods

        #region Private Methods

        private static string? TryGetPropertyValue(ManagementObject mo, string propertyName)
        {
            string? val = null;
            try
            {
                val = mo.GetPropertyValue(propertyName)?.ToString();
            }
            catch (Exception e) { Log.Verbose("Failed to fetch {0} from {1} ({2}:{3})", propertyName, mo.Path, e.GetType(), e.Message); }
            return val;
        }

        private void ProcessManagementObject(ManagementObject service)
        {
            try
            {
                var val = TryGetPropertyValue(service, "Name");
                if (val != null)
                {
                    var obj = new ServiceObject(val);

                    val = TryGetPropertyValue(service, "AcceptPause");
                    if (!string.IsNullOrEmpty(val))
                        obj.AcceptPause = bool.Parse(val);

                    val = TryGetPropertyValue(service, "AcceptStop");
                    if (!string.IsNullOrEmpty(val))
                        obj.AcceptStop = bool.Parse(val);

                    obj.Caption = TryGetPropertyValue(service, "Caption");

                    val = TryGetPropertyValue(service, "CheckPoint");
                    if (!string.IsNullOrEmpty(val))
                        obj.CheckPoint = uint.Parse(val, CultureInfo.InvariantCulture);

                    obj.CreationClassName = TryGetPropertyValue(service, "CreationClassName");

                    val = TryGetPropertyValue(service, "DelayedAutoStart");
                    if (!string.IsNullOrEmpty(val))
                        obj.DelayedAutoStart = bool.Parse(val);

                    obj.Description = TryGetPropertyValue(service, "Description");

                    val = TryGetPropertyValue(service, "DesktopInteract");
                    if (!string.IsNullOrEmpty(val))
                        obj.DesktopInteract = bool.Parse(val);

                    obj.DisplayName = TryGetPropertyValue(service, "DisplayName");
                    obj.ErrorControl = TryGetPropertyValue(service, "ErrorControl");

                    val = TryGetPropertyValue(service, "ExitCode");
                    if (!string.IsNullOrEmpty(val))
                        obj.ExitCode = uint.Parse(val, CultureInfo.InvariantCulture);

                    if (DateTime.TryParse(service.GetPropertyValue("InstallDate")?.ToString(), out DateTime dateTime))
                    {
                        obj.InstallDate = dateTime;
                    }
                    obj.PathName = TryGetPropertyValue(service, "PathName");

                    val = TryGetPropertyValue(service, "ProcessId");
                    if (!string.IsNullOrEmpty(val))
                        obj.ProcessId = uint.Parse(val, CultureInfo.InvariantCulture);

                    val = TryGetPropertyValue(service, "ServiceSpecificExitCode");
                    if (!string.IsNullOrEmpty(val))
                        obj.ServiceSpecificExitCode = uint.Parse(val, CultureInfo.InvariantCulture);

                    obj.ServiceType = TryGetPropertyValue(service, "ServiceType");

                    val = TryGetPropertyValue(service, "Started");
                    if (!string.IsNullOrEmpty(val))
                        obj.Started = bool.Parse(val);

                    obj.StartMode = TryGetPropertyValue(service, "StartMode");
                    obj.StartName = TryGetPropertyValue(service, "StartName");
                    obj.State = TryGetPropertyValue(service, "State");
                    obj.Status = TryGetPropertyValue(service, "Status");
                    obj.SystemCreationClassName = TryGetPropertyValue(service, "SystemCreationClassName");
                    obj.SystemName = TryGetPropertyValue(service, "SystemName");

                    val = TryGetPropertyValue(service, "TagId");
                    if (!string.IsNullOrEmpty(val))
                        obj.TagId = uint.Parse(val, CultureInfo.InvariantCulture);

                    val = TryGetPropertyValue(service, "WaitHint");
                    if (!string.IsNullOrEmpty(val))
                        obj.WaitHint = uint.Parse(val, CultureInfo.InvariantCulture);

                    HandleChange(obj);
                }
            }
            catch (Exception e) when (
                e is TypeInitializationException ||
                e is PlatformNotSupportedException)
            {
                Log.Warning(Strings.Get("CollectorNotSupportedOnPlatform"), GetType().ToString());
            }
            catch (Exception e)
            {
                Log.Warning(e, "Failed to grok Service Collector object at {0}.", service.Path);
            }
        }

        #endregion Private Methods
    }
}