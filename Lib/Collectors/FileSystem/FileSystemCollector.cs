// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Collectors.FileSystem
{
    /// <summary>
    /// Collects metadata from the local file system.
    /// </summary>
    public class FileSystemCollector : BaseCollector
    {
        private readonly Func<FileSystemInfo, bool> filter;
        private readonly HashSet<string> roots;

        private bool INCLUDE_CONTENT_HASH = false;
        private static readonly string SQL_TRUNCATE = "delete from file_system where run_id=@run_id";
        private static readonly string SQL_INSERT = "insert into file_system (run_id, row_key, path, permissions, size, hash, data_hash) values (@run_id, @row_key, @path, @permissions, @size, @hash, @data_hash)";

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

        public void Write(FileSystemObject obj)
        {
            _numCollected++;

            try { 
                var cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@run_id", runId);
                cmd.Parameters.AddWithValue("@row_key", obj.RowKey);
                cmd.Parameters.AddWithValue("@path", obj.Path);
                cmd.Parameters.AddWithValue("@permissions", obj.Permissions ?? "");
                cmd.Parameters.AddWithValue("@size", obj.Size);
                cmd.Parameters.AddWithValue("@hash", obj.ContentHash ?? "");
                cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));
                cmd.ExecuteNonQuery();
            }
            catch (NullReferenceException e)
            {
                Logger.Instance.Info(e.StackTrace);
            }

            if (_numCollected % 1000 == 0)
            {
                DatabaseManager.Commit();
            }
        }

        public override void Execute()
        {
            if (!CanRunOnPlatform())
            { 
                return;
            }

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
                Logger.Instance.Debug("adding root " + root.ToString());
                try
                {
                    // @TODO: Rewrite this. Walk directory traverses the whole tree already, so this is super inefficient
                    // Either move and integrate directory walking code here. Or use Actions for the walker to alert
                    var fileInfoEnumerable = DirectoryWalker.WalkDirectory(root, this.filter);
                    Parallel.ForEach(fileInfoEnumerable, (fileInfo =>
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
                            Write(obj);
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

            DatabaseManager.Commit();
            Stop();
        }
    }
}