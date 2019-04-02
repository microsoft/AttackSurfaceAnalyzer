// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
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

                if (Filter.IsFiltered(Filter.RuntimeString(), "Scan", "File", "Path", "Exclude", currentDir))
                {
                    //Logger.Instance.Debug("Excluding: {0}", currentDir);
                    continue;
                }
                else
                {
                    //Logger.Instance.Debug("Not excluding: {0}", currentDir);
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
                catch (UnauthorizedAccessException e)
                {
                    Logger.Instance.Debug(e.Message);
                    continue;
                }
                catch (System.IO.DirectoryNotFoundException e)
                {
                    Logger.Instance.Debug(e.Message);
                    continue;
                }
                // @TODO: Improve this catch. 
                // This catches a case where we sometimes try to walk a file
                // even though its not a directory on Mac OS.
                // System.IO.Directory.GetDirectories is how we get the 
                // directories.
                catch (Exception)
                {
                    //Logger.Instance.Debug(ex.StackTrace);
                    continue;
                }

                string[] files = null;
                try
                {
                    files = System.IO.Directory.GetFiles(currentDir);
                }

                catch (UnauthorizedAccessException e)
                {

                    Logger.Instance.Debug(e.Message);
                    continue;
                }

                catch (System.IO.DirectoryNotFoundException e)
                {
                    Logger.Instance.Debug(e.Message);
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
                        Logger.Instance.Debug(e.Message);
                        continue;
                    }
                    string FullPath = String.Format("{0}{1}{2}", currentDir, Path.PathSeparator, file);
                    if (Filter.IsFiltered(Filter.RuntimeString(), "Scan", "File", "Path", "Exclude", FullPath))
                    {
                        Logger.Instance.Debug("Excluding: {0}", FullPath);
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
                        if (fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                        {
                            continue;
                        }
                    }
                    catch (System.IO.DirectoryNotFoundException e)
                    {
                        // If file was deleted by a separate application
                        //  or thread since the call to TraverseTree()
                        // then just continue.
                        Logger.Instance.Debug(e.Message);
                        continue;
                    }
                    catch (Exception e)
                    {
                        Logger.Instance.Debug(e.Message);
                        continue;
                    }
                    dirs.Push(str);
                    yield return fileInfo;
                }
            }
        }
    }
}