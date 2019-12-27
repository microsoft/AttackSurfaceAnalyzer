// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DirectoryWalker
    {
        public static IEnumerable<FileSystemInfo> WalkDirectory(string root)
        {
            // Data structure to hold names of subfolders to be
            // examined for files.
            Stack<string> dirs = new Stack<string>();

            if (System.IO.Directory.Exists(root))
            {
                dirs.Push(root);
            }

            while (dirs.Count > 0)
            {
                string currentDir = dirs.Pop();
                if (Filter.IsFiltered(AsaHelpers.GetPlatformString(), "Scan", "File", "Path", currentDir))
                {
                    continue;
                }
                else
                {
                    DirectoryInfo fileInfo = null;
                    try
                    {
                        Log.Verbose("Spooling up {0}",currentDir);
                        fileInfo = new DirectoryInfo(currentDir);
                        // Skip symlinks to avoid loops
                        // Future improvement: log it as a symlink in the data
                        if (fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                        {
                            Log.Verbose($"Skipping symlink at {currentDir}");
                            continue;
                        }
                    }
                    catch (Exception e) when (
                        e is DirectoryNotFoundException
                        || e is IOException
                        || e is UnauthorizedAccessException)
                    {
                        continue;
                    }
                    catch (Exception e)
                    {
                        Log.Debug($"Should be catching {e.GetType().ToString()} in WalkDirectory");
                    }

                    yield return fileInfo;
                }

                string[] subDirs;
                try
                {
                    Log.Verbose("Getting directories {0}", currentDir);
                    subDirs = Directory.GetDirectories(currentDir);
                    Log.Verbose("Got directories {0}", currentDir);
                }
                catch (Exception e) when (
                    e is ArgumentException ||
                    e is ArgumentNullException ||
                    e is PathTooLongException ||
                    e is IOException ||
                    e is DirectoryNotFoundException ||
                    e is UnauthorizedAccessException)
                {
                    Log.Verbose("Failed to get Directories for {0} {1}", currentDir, e.GetType().ToString());
                    continue;
                }

                string[] files;
                try
                {
                    Log.Verbose("Getting files {0}", currentDir);
                    files = Directory.GetFiles(currentDir);
                    Log.Verbose("Got files {0}", currentDir);
                }

                catch (Exception e) when (
                    e is UnauthorizedAccessException ||
                    e is IOException ||
                    e is ArgumentException ||
                    e is ArgumentNullException ||
                    e is PathTooLongException ||
                    e is DirectoryNotFoundException)
                {
                    Log.Verbose("Failed to get files for {0} {1}", currentDir, e.GetType().ToString());
                    continue;
                }
                
                // Perform the required action on each file here.
                foreach (string file in files)
                {
                    if (Filter.IsFiltered(AsaHelpers.GetPlatformString(), "Scan", "File", "Path", file))
                    {
                        continue;
                    }

                    FileInfo fileInfo = null;
                    try
                    {
                        Log.Verbose("Getting FileInfo {0}", file);
                        fileInfo = new FileInfo(file);
                        Log.Verbose("Got FileInfo {0}", file);
                    }
                    catch (Exception e) when (
                        e is ArgumentNullException ||
                        e is SecurityException ||
                        e is ArgumentException ||
                        e is UnauthorizedAccessException ||
                        e is PathTooLongException ||
                        e is NotSupportedException)
                    {
                        Log.Verbose("Failed to create FileInfo from File at {0} {1}", file, e.GetType().ToString());
                        continue;
                    }

                    yield return fileInfo;
                }

                // Push the subdirectories onto the stack for traversal.
                // This could also be done before handing the files.
                foreach (string dir in subDirs)
                {
                    DirectoryInfo fileInfo = null;
                    try
                    {
                        fileInfo = new DirectoryInfo(dir);

                        // Skip symlinks to avoid loops
                        // Future improvement: log it as a symlink in the data
                        if (fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                        {
                            continue;
                        }
                    }
                    catch (Exception e) when (
                        e is SecurityException
                        || e is ArgumentException
                        || e is ArgumentException
                        || e is PathTooLongException)
                    {
                        Log.Verbose("Failed to create DirectoryInfo from Directory at {0} {1}", dir, e.GetType().ToString());
                        continue;
                    }
                    

                    if (fileInfo != null)
                    {
                        dirs.Push(dir);
                    }
                }
            }
        }
    }
}