// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Data.HashFunction.xxHash;
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

        protected internal static string GetFileHash(FileSystemInfo fileInfo)
        {
            Logger.Instance.Info(fileInfo.FullName);

            string hashValue = null;
            try
            {
                var hashFunction = xxHashFactory.Instance.Create();
                using (var stream = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read))
                {
                    hashValue = hashFunction.ComputeHash(stream).AsBase64String();
                }
            }
            catch (Exception ex)
            {
                Logger.Instance.Warn("Unable to take hash of file: {0}: {1}", fileInfo.FullName, ex.Message);
            }
            return hashValue;
        }
    }
}