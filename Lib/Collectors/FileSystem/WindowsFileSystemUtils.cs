// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.IO;
using System.Security.AccessControl;
using AttackSurfaceAnalyzer.Utils;

namespace AttackSurfaceAnalyzer.Collectors.FileSystem
{
    public class WindowsFileSystemUtils
    {
        protected internal static string GetFilePermissions(FileSystemInfo fileInfo)
        {
            FileSystemSecurity fileSecurity = null;
            var filename = fileInfo.FullName;
            if (filename.Length >= 260 && !filename.StartsWith(@"\\?\"))
            {
                filename = string.Format(@"\\?\{0}", filename);
            }

            if (fileInfo is FileInfo)
            {
                try
                {
                    fileSecurity = new FileSecurity(filename, AccessControlSections.All);
                }
                catch (Exception ex)
                {
                    Logger.Instance.Debug("Unable to get access control for {0}: {1}", fileInfo.FullName, ex.Message);
                    //Logger.Instance.Debug(ex.StackTrace);
                }
            }
            else if (fileInfo is DirectoryInfo)
            {
                try
                {
                    fileSecurity = new DirectorySecurity(filename, AccessControlSections.All);
                }
                catch (Exception ex)
                {
                    Logger.Instance.Debug("Unable to get access control for {0}: {1}", fileInfo.FullName, ex.Message);
                    //Logger.Instance.Debug(ex.StackTrace);

                }
            }
            else
            {
                return null;
            }
            if (fileSecurity != null)
                return fileSecurity.GetSecurityDescriptorSddlForm(AccessControlSections.All);
            else
                return null;
        }
    }
}