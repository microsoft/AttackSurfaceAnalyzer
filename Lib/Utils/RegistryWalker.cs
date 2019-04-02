// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;

namespace AttackSurfaceAnalyzer.Utils
{
    public class RegistryWalker
    {     
        public static IEnumerable<RegistryKey> WalkHive(RegistryHive Hive)
        {
            // Data structure to hold names of subfolders to be
            // examined for files.
            Stack<RegistryKey> keys = new Stack<RegistryKey>();

            //if (!System.IO.Directory.Exists(root))
            //{
            //    throw new ArgumentException("Unable to find [" + root + "]");
            //}
            RegistryKey BaseKey = RegistryKey.OpenBaseKey(Hive, RegistryView.Default);

            keys.Push(BaseKey);

            while (keys.Count > 0)
            {

            
                RegistryKey currentKey = keys.Pop();
                string[] subKeys = currentKey.GetSubKeyNames();



                // An UnauthorizedAccessException exception will be thrown if we do not have
                // discovery permission on a folder or file. It may or may not be acceptable 
                // to ignore the exception and continue enumerating the remaining files and 
                // folders. It is also possible (but unlikely) that a DirectoryNotFound exception 
                // will be raised. This will happen if currentDir has been deleted by
                // another application or thread after our call to Directory.Exists. The 
                // choice of which exceptions to catch depends entirely on the specific task 
                // you are intending to perform and also on how much you know with certainty 
                // about the systems on which this code will run.
                //catch (UnauthorizedAccessException e)
                //{
                //    Logger.Instance.Debug(e.Message);
                //    continue;
                //}
                //catch (System.IO.DirectoryNotFoundException e)
                //{
                //    Logger.Instance.Debug(e.Message);
                //    continue;
                //}
                // @TODO: Improve this catch. 
                // This catches a case where we sometimes try to walk a file
                // even though its not a directory on Mac OS.
                // System.IO.Directory.GetDirectories is how we get the 
                // directories.
                //catch (Exception ex)
                //{
                //    Logger.Instance.Debug(ex.StackTrace);
                //    continue;
                //}

                Dictionary<string, string> values = new Dictionary<string, string>();
                // Write values under key and commit
                foreach (var value in currentKey.GetValueNames())
                {
                    var Value = currentKey.GetValue(value);
                    string str = "";

                    // This is okay. It is a zero-length value
                    if (Value == null)
                    {
                        // We can leave this empty
                    }

                    else if (Value.ToString() == "System.Byte[]")
                    {
                        str = Convert.ToBase64String((System.Byte[])Value);
                    }

                    else if (Value.ToString() == "System.String[]")
                    {
                        str = "";
                        foreach (String st in (System.String[])Value)
                        {
                            str += st;
                        }
                    }

                    else
                    {
                        if (Value.ToString() == Value.GetType().ToString())
                        {
                            Logger.Instance.Warn("Uh oh, this type isn't handled. " + Value.ToString());
                        }
                        str = Value.ToString();
                    }
                    values.Add(value, str);
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
                    if (filter == null || filter(fileInfo))
                    {
                        yield return fileInfo;
                    }

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
                    if (filter == null || filter(fileInfo))
                    {
                        dirs.Push(str);
                        yield return fileInfo;
                    }
                }
            }
        }
    }
}