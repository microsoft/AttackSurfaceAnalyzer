// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.IO;
using AttackSurfaceAnalyzer.Utils;
using Mono.Unix;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class LinuxFileSystemUtils
    {

        protected internal static string GetFilePermissions(FileSystemInfo fileInfo)
        {
            var filename = fileInfo.FullName;

            FileAccessPermissions permissions = default(FileAccessPermissions);

            if (fileInfo is FileInfo)
            {
                try
                {
                    permissions = new UnixFileInfo(filename).FileAccessPermissions;
                }
                catch (Exception ex)
                {
                    Log.Warning("Unable to get access control for {0}: {1}", fileInfo.FullName, ex.Message);
                }
            }
            else if (fileInfo is DirectoryInfo)
            {
                try
                {
                    permissions = new UnixDirectoryInfo(filename).FileAccessPermissions;
                }
                catch (Exception ex)
                {
                    Log.Warning("Unable to get access control for {0}: {1}", fileInfo.FullName, ex.Message);
                }
            }
            else
            {
                return null;
            }

            return permissions.ToString();
        }
    }
}