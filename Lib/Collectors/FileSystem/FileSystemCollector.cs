// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.FileSystem
{

    public class WriteBuffer{
        private static readonly string SQL_INSERT = "insert into file_system (run_id, row_key, path, permissions, size, hash, serialized) values (@run_id, @row_key, @path, @permissions, @size, @hash, @serialized)";

        private readonly Queue<FileSystemObject> _queue = new Queue<FileSystemObject>();
        private readonly SqliteCommand cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction);

        string runId;

        private System.Timers.Timer CommitTimer = new System.Timers.Timer
        {
            Interval = 100,
            AutoReset = true,
        };

        public void Write(FileSystemObject fso)
        {
            _queue.Append(fso);
        }

        public WriteBuffer(string runId)
        {
            this.runId = runId;
            CommitTimer.Elapsed += (source, e) => 
            {
                WriteUntilEmpty(); 
            };
            CommitTimer.Enabled = true;

        }

        public void WriteUntilEmpty()
        {
            CommitTimer.Enabled = false;
            while (_queue.Count > 0)
            {
                Log.Warning(_queue.Count.ToString());
                FileSystemObject fso = _queue.Dequeue();
                Write(cmd, fso);
            }
            CommitTimer.Enabled = true;
        }


        public void Write(SqliteCommand cmd, FileSystemObject obj)
        {
            cmd.Parameters.Clear();
            cmd.Parameters.AddWithValue("@run_id", runId);
            cmd.Parameters.AddWithValue("@row_key", obj.RowKey);
            cmd.Parameters.AddWithValue("@path", obj.Path);
            cmd.Parameters.AddWithValue("@permissions", obj.Permissions ?? "");
            cmd.Parameters.AddWithValue("@size", obj.Size);
            cmd.Parameters.AddWithValue("@hash", obj.ContentHash ?? "");
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));
            try
            {
                cmd.ExecuteNonQuery();
            }
            catch (Exception e)
            {
                Log.Information(e.StackTrace);
                Log.Information(e.Message);
                Log.Information(e.GetType().ToString());
            }
        }

        public void Stop()
        {
            CommitTimer.Enabled = false;
        }

    }
    /// <summary>
    /// Collects Filesystem Data from the local file system.
    /// </summary>
    public class FileSystemCollector : BaseCollector
    {
        private readonly Func<FileSystemInfo, bool> filter;
        private readonly HashSet<string> roots;

        private bool INCLUDE_CONTENT_HASH = false;
        private static readonly string SQL_TRUNCATE = "delete from file_system where run_id=@run_id";


        private static readonly string SQL_INSERT = "insert into file_system (run_id, row_key, path, permissions, size, hash, serialized) values (@run_id, @row_key, @path, @permissions, @size, @hash, @serialized)";


        private WriteBuffer wb;

        public void Write(FileSystemObject obj)
        {
            SqliteCommand cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", runId);
            cmd.Parameters.AddWithValue("@row_key", obj.RowKey);
            cmd.Parameters.AddWithValue("@path", obj.Path);
            cmd.Parameters.AddWithValue("@permissions", obj.Permissions ?? "");
            cmd.Parameters.AddWithValue("@size", obj.Size);
            cmd.Parameters.AddWithValue("@hash", obj.ContentHash ?? "");
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));
            try
            {
                cmd.ExecuteNonQuery();
            }
            catch (Exception e)
            {
                Log.Information(e.StackTrace);
                Log.Information(e.Message);
                Log.Information(e.GetType().ToString());
            }
        }

        public FileSystemCollector(string runId, Func<FileSystemInfo, bool> filter = null, bool enableHashing = false)
        {
            Log.Debug("Initializing a new {0} object.", this.GetType().Name);
            this.filter = filter;
            this.runId = runId;
            this.roots = new HashSet<string>();
            INCLUDE_CONTENT_HASH = enableHashing;
        }

        public void Truncate(string runid)
        {
            var cmd = new SqliteCommand(SQL_TRUNCATE, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", runId);
        }

        public void AddRoot(string root)
        {
            this.roots.Add(root);
        }

        public void ClearRoots()
        {
            this.roots.Clear();
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void Execute()
        {
            if (!CanRunOnPlatform())
            { 
                return;
            }

            wb = new WriteBuffer(runId);
            Start();
            
            if (this.roots == null || this.roots.Count() == 0)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    foreach (var driveInfo in DriveInfo.GetDrives())
                    {
                        if (driveInfo.IsReady && driveInfo.DriveType == DriveType.Fixed)
                        {
                            this.roots.Add(driveInfo.Name);
                        }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    this.roots.Add("/");   // @TODO Improve this
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    this.roots.Add("/"); // @TODO Improve this
                }
            }

            foreach (var root in this.roots)
            {
                Log.Information("Scanning root {0}",root.ToString());
                try
                {
                    var fileInfoEnumerable = DirectoryWalker.WalkDirectory(root);
                    Parallel.ForEach(fileInfoEnumerable,
                                    (fileInfo =>
                    {
                        try
                        {
                            FileSystemObject obj = null;
                            if (fileInfo is DirectoryInfo)
                            {
                                if (!Filter.IsFiltered(Filter.RuntimeString(), "Scan", "File", "Path", fileInfo.FullName))
                                {
                                    obj = new FileSystemObject()
                                    {
                                        Path = fileInfo.FullName,
                                        Permissions = FileSystemUtils.GetFilePermissions(fileInfo)
                                    };
                                }
                            }
                            else
                            {
                                if (!Filter.IsFiltered(Filter.RuntimeString(), "Scan", "File", "Path", fileInfo.FullName))
                                {
                                    obj = new FileSystemObject()
                                    {
                                        Path = fileInfo.FullName,
                                        Permissions = FileSystemUtils.GetFilePermissions(fileInfo),
                                        Size = (ulong)(fileInfo as FileInfo).Length
                                    };
                                    if (INCLUDE_CONTENT_HASH)
                                    {
                                        obj.ContentHash = FileSystemUtils.GetFileHash(fileInfo);
                                    }
                                }
                            }
                            if (obj != null)
                            {
                                Write(obj);
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, "Error processing {0}", fileInfo?.FullName);
                        }
                    }));
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Error collecting file system information: {0}", ex.Message);
                }
            }

            Stop();

            DatabaseManager.Commit();
        }
    }
}