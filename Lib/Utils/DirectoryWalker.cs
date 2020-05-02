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
        public static IEnumerable<string> WalkDirectory(string root)
        {
            // Data structure to hold names of subfolders to be
            // examined for files.
            Stack<string> dirs = new Stack<string>();
            // Master list of all directories seen, to prevent loops from Hard Links.
            HashSet<string> dirsSet = new HashSet<string>();

            if (Directory.Exists(root))
            {
                dirs.Push(root);
                dirsSet.Add(root);
            }

            while (dirs.Count > 0)
            {
                string currentDir = dirs.Pop();

                yield return currentDir;

                try
                {
                    var fileInfo = new DirectoryInfo(currentDir);
                    // Skip symlinks to avoid loops
                    if (fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        Log.Verbose($"Skipping symlink at {currentDir}");
                        continue;
                    }
                }
                catch (Exception e) when (
                    e is UnauthorizedAccessException)
                {
                    Log.Verbose($"Access denied to {currentDir}");
                }
                catch (Exception e)
                {
                    Log.Debug("Should be catching {0} in DirectoryWalker.", e.GetType().ToString());
                }

                string[] subDirs;
                try
                {
                    subDirs = Directory.GetDirectories(currentDir);
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
                    files = Directory.GetFiles(currentDir);
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

                foreach (string file in files)
                {
                    yield return file;
                }

                // Push the subdirectories onto the stack for traversal.
                // This could also be done before handing the files.
                foreach (string dir in subDirs)
                {
                    try
                    {
                        if (!dirsSet.Contains(dir))
                        {
                            dirs.Push(dir);
                            dirsSet.Add(dir);
                        }
                        else
                        {
                            Log.Verbose("Loop detected. Skipping duplicate directory {0} as a subdirectory of {1}", dir, currentDir);
                        }
                    }
                    catch (Exception e) when (
                        e is SecurityException
                        || e is ArgumentException
                        || e is ArgumentException
                        || e is PathTooLongException
                        || e is UnauthorizedAccessException
                        || e is IOException)
                    {
                        Log.Verbose("Failed to create DirectoryInfo from Directory at {0} {1}", dir, e.GetType().ToString());
                        continue;
                    }
                }
            }
        }
    }
}