// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Collectors.FileSystem
{
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

        private System.Timers.Timer CommitTimer = new System.Timers.Timer
        {
            Interval = 1000,
            AutoReset = false,
        };


        private List<FileSystemObject> objList = new List<FileSystemObject>();

        private void WriteAndCommitResults()
        {
            List<FileSystemObject> commitList;

                commitList = objList.ToList();
                objList.Clear();

            var cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction);

            foreach (FileSystemObject fso in commitList)
            {
                WriteFaster(cmd, fso);
            }
            DatabaseManager.Commit();
            CommitTimer = new System.Timers.Timer
            {
                Interval = 1000,
                AutoReset = false,
            };
            CommitTimer.Enabled = true;
        }

        public FileSystemCollector(string runId, Func<FileSystemInfo, bool> filter = null, bool enableHashing = false)
        {
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

        public void WriteFaster(SqliteCommand cmd, FileSystemObject obj)
        {
            _numCollected++;
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
                Logger.Instance.Info(e.StackTrace);
                Logger.Instance.Info(e.Message);
                Logger.Instance.Info(e.GetType());
            }
        }

        void HandleLogMessageGenerator()
        {
        }

        public override void Execute()
        {
            if (!CanRunOnPlatform())
            { 
                return;
            }
            var watch = System.Diagnostics.Stopwatch.StartNew();
            // the code that you want to measure comes here

            Start();
            Truncate(runId);
            
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
                Logger.Instance.Warn("adding root " + root.ToString());
                try
                {
                    var fileInfoEnumerable = DirectoryWalker.WalkDirectory(root, this.filter);
                    // Start the timer
                    CommitTimer.Elapsed += (source, e) => { WriteAndCommitResults(); };
                    CommitTimer.Enabled = true;

                    Parallel.ForEach(fileInfoEnumerable,
                                    (fileInfo =>
                    {
                        try
                        {
                            FileSystemObject obj = default(FileSystemObject);
                            if (fileInfo is DirectoryInfo)
                            {
                                obj = new FileSystemObject()
                                {
                                    Path = fileInfo.FullName,
                                    Permissions = FileSystemUtils.GetFilePermissions(fileInfo)
                                };
                            }
                            else
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
                            objList.Add(obj);
                        }
                        catch (Exception ex)
                        {
                            Logger.Instance.Debug(ex, "Error processing {0}", fileInfo?.FullName);
                        }
                    }));
                }
                catch (Exception ex)
                {
                    Logger.Instance.Debug(ex, "Error collecting file system information: {0}", ex.Message);
                }
            }
            //turn off commit timer
            CommitTimer.Enabled = false;
            WriteAndCommitResults();
            Stop();

            watch.Stop();
            int elapsedS = (int)watch.ElapsedMilliseconds/1000;
            Logger.Instance.Info("Completed FileSystemCollector in " + elapsedS);
        }
    }
}