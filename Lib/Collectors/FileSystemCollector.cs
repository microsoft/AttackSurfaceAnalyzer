// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects Filesystem Data from the local file system.
    /// </summary>
    public class FileSystemCollector : BaseCollector
    {
        private readonly HashSet<string> roots;

        private bool INCLUDE_CONTENT_HASH = false;

        bool downloadCloud;

        public FileSystemCollector(string runId, bool enableHashing = false, string directories = "", bool downloadCloud = false)
        {
            this.runId = runId;
            this.downloadCloud = downloadCloud;

            roots = new HashSet<string>();
            INCLUDE_CONTENT_HASH = enableHashing;

            if (!directories.Equals("")) 
            { 
                foreach (string path in directories.Split(','))
                {
                    AddRoot(path);
                }
            }

        }

        public void AddRoot(string root)
        {
            roots.Add(root);
        }

        public void ClearRoots()
        {
            roots.Clear();
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

            Start();
            //Ensure the transaction is started to prevent collisions on the multithreaded code ahead
            _ = DatabaseManager.Transaction;
            
            if (roots == null || !roots.Any())
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    foreach (var driveInfo in DriveInfo.GetDrives())
                    {
                        if (driveInfo.IsReady && driveInfo.DriveType == DriveType.Fixed)
                        {
                            roots.Add(driveInfo.Name);
                        }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    roots.Add("/");   // @TODO Improve this
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    roots.Add("/"); // @TODO Improve this
                }
            }

            foreach (var root in roots)
            {
                Log.Information("{0} root {1}",Strings.Get("Scanning"),root.ToString());
                try
                {
                    var fileInfoEnumerable = DirectoryWalker.WalkDirectory(root, Helpers.GetPlatformString());
                    Parallel.ForEach(fileInfoEnumerable,
                                    (fileInfo =>
                    {
                        try
                        {
                            FileSystemObject obj = null;
                            if (fileInfo is DirectoryInfo)
                            {
                                obj = new FileSystemObject()
                                {
                                    Path = fileInfo.FullName,
                                    Permissions = FileSystemUtils.GetFilePermissions(fileInfo),
                                    IsDirectory = true
                                };
                            }
                            else
                            {
                                obj = new FileSystemObject()
                                {
                                    Path = fileInfo.FullName,
                                    Permissions = FileSystemUtils.GetFilePermissions(fileInfo),
                                    Size = (ulong)(fileInfo as FileInfo).Length,
                                    IsDirectory = false
                                };

                                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                                {
                                    if (WindowsFileSystemUtils.IsLocal(obj.Path) || downloadCloud)
                                    {
                                        if (WindowsFileSystemUtils.NeedsSignature(obj.Path))
                                        {
                                            obj.SignatureStatus = WindowsFileSystemUtils.GetSignatureStatus(fileInfo.FullName);
                                            obj.Characteristics = WindowsFileSystemUtils.GetDllCharacteristics(fileInfo.FullName);
                                        }
                                        else
                                        {
                                            obj.SignatureStatus = "Cloud";
                                        }
                                    }
                                }

                                if (INCLUDE_CONTENT_HASH)
                                {
                                    obj.ContentHash = FileSystemUtils.GetFileHash(fileInfo);
                                }

                                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                                {
                                    if (obj.Permissions.Contains("Execute"))
                                    {
                                        obj.IsExecutable = true;
                                    }
                                }
                                else
                                {
                                    try
                                    {
                                        if (WindowsFileSystemUtils.NeedsSignature(obj.Path))
                                        {
                                            obj.IsExecutable = true;
                                        }
                                    }
                                    catch (System.UnauthorizedAccessException)
                                    {
                                        Log.Verbose("Couldn't access {0} to check if signature is needed.");
                                    }
                                }
                            }

                            if (obj != null)
                            {
                                DatabaseManager.Write(obj,runId);
                            }
                        }
                        catch (System.UnauthorizedAccessException ex)
                        {
                            Log.Verbose(ex, "Access Denied {0}", fileInfo?.FullName);
                        }
                        catch (System.IO.IOException ex)
                        {
                            Log.Verbose(ex, "Access Denied {0}", fileInfo?.FullName);
                        }
                        catch (Exception ex)
                        {
                            Log.Debug(ex, "Access Denied {0}", fileInfo?.FullName);
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