// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Actively monitors the filesystem for changes.
    /// </summary>
    public class FileSystemMonitor : BaseMonitor, IDisposable
    {
        private const string SQL_TRUNCATE = "delete from file_system_monitored where run_id=@run_id";
        private const string SQL_INSERT = "insert into file_system_monitored (run_id, row_key, timestamp, change_type, path, old_path, name, old_name, extended_results, notify_filters, serialized) values (@run_id, @row_key, @timestamp, @change_type, @path, @old_path, @name, @old_name, @extended_results, @notify_filters, @serialized)";

        private FileSystemWatcher watcher;

        public static readonly NotifyFilters defaultFilters = NotifyFilters.Attributes
                | NotifyFilters.CreationTime
                | NotifyFilters.DirectoryName
                | NotifyFilters.FileName
                | NotifyFilters.LastWrite
                | NotifyFilters.Security
                | NotifyFilters.Size;

        public static readonly NotifyFilters defaultFiltersWithAccessTime = defaultFilters | NotifyFilters.LastAccess;

        private Action<EventArgs> customChangeHandler = null;

        private bool getFileDetails = true;

        public override void StartRun()
        {
            watcher.EnableRaisingEvents = true;
            RunStatus = RUN_STATUS.RUNNING;

        }
        public override void StopRun()
        {
            watcher.EnableRaisingEvents = false;
            RunStatus = RUN_STATUS.COMPLETED;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public static void Truncate(string RunId)
        {
            using var cmd = new SqliteCommand(SQL_TRUNCATE, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", RunId);
        }

        /// <summary>
        /// This initializer ensures that the access time filter isn't used with InterrogateChanges, which causes a loop.
        /// </summary>
        public FileSystemMonitor(string runId, string dir, bool interrogateChanges) : this(runId, dir, interrogateChanges, interrogateChanges ? defaultFilters : defaultFiltersWithAccessTime) { }

        // @TODO: Add ability to filter file name/type
        // @TODO: Initialize database if not done yet, was previously factored out
        // This constructor allows you to specify the NotifyFilters which were used
        public FileSystemMonitor(string runId, string dir, bool interrogateChanges, NotifyFilters filters)
        {
            this.RunId = runId;
            Truncate(runId);
            this.getFileDetails = interrogateChanges;

            watcher = new FileSystemWatcher();

            watcher.Path = dir;

            watcher.NotifyFilter = filters;

            watcher.IncludeSubdirectories = true;

            // Changed, Created and Deleted can share a handler, because they throw the same type of event
            watcher.Changed += OnChanged;
            watcher.Created += OnChanged;
            watcher.Deleted += OnChanged;

            // Renamed needs a different handler because it throws a different kind of event
            watcher.Renamed += OnRenamed;
        }

        public bool IsRunning()
        {
            return watcher.EnableRaisingEvents;
        }

        public void WriteChange(FileSystemEventArgs objIn)
        {
            if (objIn != null)
            {
                string timestamp = DateTime.Now.ToString("O", CultureInfo.InvariantCulture);

                using var cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@run_id", this.RunId);
                cmd.Parameters.AddWithValue("@row_key", CryptoHelpers.CreateHash(objIn.ToString() + timestamp + watcher.NotifyFilter.ToString() + objIn.ChangeType.ToString()));
                cmd.Parameters.AddWithValue("@timestamp", timestamp);
                cmd.Parameters.AddWithValue("@path", objIn.FullPath);
                cmd.Parameters.AddWithValue("@old_path", "");
                cmd.Parameters.AddWithValue("@name", objIn.Name);
                cmd.Parameters.AddWithValue("@old_name", "");
                cmd.Parameters.AddWithValue("@change_type", ChangeTypeStringToChangeType(objIn.ChangeType.ToString()));
                cmd.Parameters.AddWithValue("@extended_results", "");
                cmd.Parameters.AddWithValue("@notify_filters", watcher.NotifyFilter.ToString());
                cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(objIn));
                FileSystemMonitorResult fileSystemObject = new FileSystemMonitorResult()
                {
                    evt = objIn,
                    filter = watcher.NotifyFilter
                };

                cmd.ExecuteNonQuery();
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

        public void WriteChange(FileSystemEventArgs objIn, string details)
        {
            if (objIn != null)
            {
                var evt = new FileMonitorEvent()
                {
                    ChangeType = ChangeTypeToChangeType(objIn.ChangeType),
                    Path = objIn.FullPath,
                    Name = objIn.Name
                };
                string timestamp = DateTime.Now.ToString("O",CultureInfo.InvariantCulture);

                using var cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@run_id", this.RunId);
                cmd.Parameters.AddWithValue("@row_key", CryptoHelpers.CreateHash(objIn.ToString() + timestamp + watcher.NotifyFilter.ToString() + objIn.ChangeType.ToString()));
                cmd.Parameters.AddWithValue("@timestamp", timestamp);
                cmd.Parameters.AddWithValue("@path", objIn.FullPath);
                cmd.Parameters.AddWithValue("@old_path", "");
                cmd.Parameters.AddWithValue("@name", objIn.Name);
                cmd.Parameters.AddWithValue("@old_name", "");
                cmd.Parameters.AddWithValue("@change_type", ChangeTypeToChangeType(objIn.ChangeType));
                cmd.Parameters.AddWithValue("@extended_results", details);
                cmd.Parameters.AddWithValue("@notify_filters", watcher.NotifyFilter.ToString());
                cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(evt));

                cmd.ExecuteNonQuery();
            }
        }

        public void WriteRename(RenamedEventArgs objIn)
        {
            if (objIn == null) { return; }
            var evt = new FileMonitorEvent()
            {
                ChangeType = ChangeTypeToChangeType(objIn.ChangeType),
                Path = objIn.FullPath,
                Name = objIn.Name,
                OldPath = objIn.OldFullPath,
                OldName = objIn.OldName
            };

            string timestamp = DateTime.Now.ToString("O", CultureInfo.InvariantCulture);

            using var cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", this.RunId);
            cmd.Parameters.AddWithValue("@row_key", CryptoHelpers.CreateHash(objIn.ToString() + timestamp + watcher.NotifyFilter.ToString() + objIn.ChangeType.ToString()));
            cmd.Parameters.AddWithValue("@timestamp", timestamp);
            cmd.Parameters.AddWithValue("@path", objIn.FullPath);
            cmd.Parameters.AddWithValue("@old_path", objIn.OldFullPath ?? "");
            cmd.Parameters.AddWithValue("@name", objIn.Name ?? "");
            cmd.Parameters.AddWithValue("@old_name", objIn.OldName ?? "");
            cmd.Parameters.AddWithValue("@change_type", ChangeTypeToChangeType(objIn.ChangeType));
            cmd.Parameters.AddWithValue("@extended_results", "");
            cmd.Parameters.AddWithValue("@notify_filters", watcher.NotifyFilter.ToString());
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(evt));

            cmd.ExecuteNonQuery();
        }


        private void OnChanged(object source, FileSystemEventArgs e)
        {
            if (Filter.IsFiltered(AsaHelpers.GetPlatformString(), "Monitor", "File", "Path", e.FullPath))
            {
                return;
            }

            // Inspect the file
            if (getFileDetails && e.ChangeType != WatcherChangeTypes.Deleted)
            {
                // Switch to using Mono here
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    var unixFileInfo = new Mono.Unix.UnixFileInfo(e.FullPath);
                    var result = unixFileInfo.FileAccessPermissions.ToString();
                    WriteChange(e, result);
                    return;
                }
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // Found this example but it isn't working on osx
                    //FileSecurity fSecurity = File.GetAccessControl(e.FullPath);
                }
            }
            WriteChange(e);
            customChangeHandler?.Invoke(e);
        }

        private void OnRenamed(object source, RenamedEventArgs e)
        {
            if (Filter.IsFiltered(AsaHelpers.GetPlatformString(), "Monitor", "File", "Path", e.FullPath))
            {
                return;
            }

            WriteRename(e);
        }

        public void SetCustomChangeHandler(Action<EventArgs> handler)
        {
            this.customChangeHandler = handler;
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
                if (watcher != null)
                {
                    watcher.Dispose();
                    watcher = null;
                }
            }
        }
    }
}