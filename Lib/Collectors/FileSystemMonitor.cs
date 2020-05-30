// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Actively monitors the filesystem for changes.
    /// </summary>
    public class FileSystemMonitor : BaseMonitor, IDisposable
    {
        private List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();

        public static readonly NotifyFilters defaultFilters = NotifyFilters.Attributes
                | NotifyFilters.CreationTime
                | NotifyFilters.DirectoryName
                | NotifyFilters.FileName
                | NotifyFilters.LastWrite
                | NotifyFilters.Security
                | NotifyFilters.Size;

        public static readonly NotifyFilters defaultFiltersWithAccessTime = defaultFilters | NotifyFilters.LastAccess;

        private readonly MonitorCommandOptions options;

        private readonly FileSystemCollector fsc;

        public override void StartRun()
        {
            watchers.ForEach(x => x.EnableRaisingEvents = true);
            RunStatus = RUN_STATUS.RUNNING;

        }
        public override void StopRun()
        {
            watchers.ForEach(x => x.EnableRaisingEvents = false);
            RunStatus = RUN_STATUS.COMPLETED;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public FileSystemMonitor(MonitorCommandOptions opts)
        {
            options = opts ?? new MonitorCommandOptions();
            RunId = options.RunId;

            fsc = new FileSystemCollector(new CollectCommandOptions()
            {
                DownloadCloud = false,
                GatherHashes = options.GatherHashes,
            });

            foreach(var dir in options.MonitoredDirectories?.Split(',') ?? fsc.Roots.ToArray())
            {
                var watcher = new FileSystemWatcher();

                watcher.Path = dir;

                watcher.NotifyFilter = options.InterrogateChanges ? defaultFilters : defaultFiltersWithAccessTime;

                watcher.IncludeSubdirectories = true;

                // Changed, Created and Deleted can share a handler, because they throw the same type of event
                watcher.Changed += OnChanged;
                watcher.Created += OnChanged;
                watcher.Deleted += OnChanged;

                // Renamed needs a different handler because it throws a different kind of event
                watcher.Renamed += OnRenamed;

                watchers.Add(watcher);
            }
        }

        public bool IsRunning()
        {
            return watchers.Any(x => x.EnableRaisingEvents);
        }

        public void WriteChange(FileSystemEventArgs objIn)
        {
            if (objIn != null)
            {
                var ToWrite = new FileMonitorObject(objIn.FullPath)
                {
                    ResultType = RESULT_TYPE.FILEMONITOR,
                    ChangeType = ChangeTypeStringToChangeType(objIn.ChangeType.ToString()),
                    Name = objIn.Name,
                    Timestamp = DateTime.Now.ToString("O", CultureInfo.InvariantCulture),
                    FileSystemObject = (objIn.ChangeType == WatcherChangeTypes.Deleted || !options.InterrogateChanges) ? null : fsc.FilePathToFileSystemObject(objIn.FullPath)
                };

                DatabaseManager.WriteFileMonitor(ToWrite, RunId);
            }
        }

        private static CHANGE_TYPE ChangeTypeStringToChangeType(string change_type)
        {
            if (change_type.Equals("Changed"))
            {
                return CHANGE_TYPE.MODIFIED;
            }
            if (change_type.Equals("Created"))
            {
                return CHANGE_TYPE.CREATED;
            }
            if (change_type.Equals("Renamed"))
            {
                return CHANGE_TYPE.RENAMED;
            }
            if (change_type.Equals("Deleted"))
            {
                return CHANGE_TYPE.DELETED;
            }
            return CHANGE_TYPE.INVALID;
        }

        public static CHANGE_TYPE ChangeTypeToChangeType(WatcherChangeTypes changeType)
        {
            switch (changeType)
            {
                case WatcherChangeTypes.Changed:
                    return CHANGE_TYPE.MODIFIED;
                case WatcherChangeTypes.Created:
                    return CHANGE_TYPE.CREATED;
                case WatcherChangeTypes.Deleted:
                    return CHANGE_TYPE.DELETED;
                case WatcherChangeTypes.Renamed:
                    return CHANGE_TYPE.RENAMED;
                default:
                    return CHANGE_TYPE.INVALID;
            }
        }

        public void WriteRename(RenamedEventArgs objIn)
        {
            if (objIn == null) { return; }

            var ToWrite = new FileMonitorObject(objIn.FullPath)
            {
                ResultType = RESULT_TYPE.FILEMONITOR,
                ChangeType = ChangeTypeStringToChangeType(objIn.ChangeType.ToString()),
                OldPath = objIn.OldFullPath,
                Name = objIn.Name,
                OldName = objIn.OldName,
                Timestamp = DateTime.Now.ToString("O", CultureInfo.InvariantCulture)
            };

            DatabaseManager.WriteFileMonitor(ToWrite, RunId);
        }


        private void OnChanged(object source, FileSystemEventArgs e)
        {
            if (InvalidFile(e.FullPath))
            {
                return;
            }

            WriteChange(e);
        }

        // These files cause loops on MAC OS as they get changed whenever text is pasted to the console
        private readonly Regex uuidText = new Regex("/private/var/db/uuidtext", RegexOptions.Compiled);
        private bool InvalidFile(string Path)
        {
            return uuidText.IsMatch(Path);
        }

        private void OnRenamed(object source, RenamedEventArgs e)
        {
            if (InvalidFile(e.FullPath))
            {
                return;
            }

            WriteRename(e);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                watchers.ForEach(x => x.Dispose());
            }
        }
    }
}