// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;

namespace AttackSurfaceAnalyzer.Utils
{
    public class DirectoryWalker
    {
        public static IEnumerable<FileSystemInfo> WalkDirectory(string root)
        {
            // Data structure to hold names of subfolders to be
            // examined for files.
            Stack<string> dirs = new Stack<string>();

            if (!System.IO.Directory.Exists(root))
            {
                throw new ArgumentException("Unable to find [" + root + "]");
            }
            dirs.Push(root);

            while (dirs.Count > 0)
            {
                string currentDir = dirs.Pop();
                if (Filter.IsFiltered(Helpers.GetPlatformString(), "Scan", "File", "Path", currentDir))
                {
                    continue;
                }

                string[] subDirs;
                try
                {
                    subDirs = System.IO.Directory.GetDirectories(currentDir);
                }
                // An UnauthorizedAccessException exception will be thrown if we do not have
                // discovery permission on a folder or file. It may or may not be acceptable 
                // to ignore the exception and continue enumerating the remaining files and 
                // folders. It is also possible (but unlikely) that a DirectoryNotFound exception 
                // will be raised. This will happen if currentDir has been deleted by
                // another application or thread after our call to Directory.Exists. The 
                // choice of which exceptions to catch depends entirely on the specific task 
                // you are intending to perform and also on how much you know with certainty 
                // about the systems on which this code will run.
                catch (UnauthorizedAccessException)
                {
                    Log.Debug("Unable to access: {0}", currentDir);
                    continue;
                }
                catch (System.IO.DirectoryNotFoundException)
                {
                    Log.Debug("Directory not found: {0}", currentDir);
                    continue;
                }
                // @TODO: Improve this catch. 
                // This catches a case where we sometimes try to walk a file
                // even though its not a directory on Mac OS.
                // System.IO.Directory.GetDirectories is how we get the 
                // directories which sometimes gives you things that aren't directories.
                catch (Exception e)
                {
                    Logger.DebugException(e);
                    continue;
                }

                string[] files = null;
                try
                {
                    files = System.IO.Directory.GetFiles(currentDir);
                }

                catch (UnauthorizedAccessException e)
                {

                    Log.Debug(e.Message);
                    continue;
                }

                catch (System.IO.DirectoryNotFoundException e)
                {
                    Log.Debug(e.Message);
                    continue;
                }
                // Perform the required action on each file here.
                // Modify this block to perform your required task.
                foreach (string file in files)
                {
                    FileInfo fileInfo = null;
                    try
                    {
                        fileInfo = new FileInfo(file);
                    }
                    catch (System.IO.FileNotFoundException e)
                    {
                        // If file was deleted by a separate application
                        //  or thread since the call to TraverseTree()
                        // then just continue.
                        Log.Debug(e.Message);
                        continue;
                    }
                    if (Filter.IsFiltered(Helpers.GetPlatformString(), "Scan", "File", "Path", file))
                    {
                        continue;
                    }
                    yield return fileInfo;

                }

                // Push the subdirectories onto the stack for traversal.
                // This could also be done before handing the files.
                foreach (string str in subDirs)
                {
                    DirectoryInfo fileInfo = null;
                    try
                    {
                        fileInfo = new DirectoryInfo(str);

                        // Skip symlinks to avoid loops
                        // Future improvement: log it as a symlink in the data
                        if (fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                        {
                            continue;
                        }
                    }
                    catch (System.IO.DirectoryNotFoundException)
                    {
                        // If file was deleted by a separate application
                        //  or thread since the call to TraverseTree()
                        // then just continue.
                        continue;
                    }
                    catch (Exception e)
                    {
                        Logger.DebugException(e);

                        Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Warning, e);
                        continue;
                    }
                    dirs.Push(str);
                    yield return fileInfo;
                }
            }
        }
    }
}