// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Utils;
using Mono.Unix;
using Serilog;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class LinuxFileSystemUtils
    {
        public static bool IsExecutable(string Path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                try
                {
                    var fourBytes = new byte[4];
                    using (var fileStream = File.Open(Path, FileMode.Open))
                    {
                        fileStream.Read(fourBytes, 0, 4);
                    }
                    // ELF Format magic number " ELF"
                    return (Encoding.ASCII.GetString(fourBytes) == Helpers.HexStringToAscii("7F454C46"));
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }
                catch (Exception e)
                {
                    Logger.DebugException(e);
                    return false;
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                try
                {
                    var fourBytes = new byte[4];
                    using (var fileStream = File.Open(Path, FileMode.Open))
                    {
                        fileStream.Read(fourBytes, 0, 4);
                    }
                    // Mach-o format magic numbers
                    return (Encoding.ASCII.GetString(fourBytes) == Helpers.HexStringToAscii("FEEDFACE")) || (Encoding.ASCII.GetString(fourBytes) == Helpers.HexStringToAscii("FEEDFACF"));
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }
                catch (Exception e)
                {
                    Logger.DebugException(e);
                    return false;
                }
            }
            return false;
        }

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
                    Log.Debug("Unable to get access control for {0}: {1}", fileInfo.FullName, ex.Message);
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
                    Log.Debug("Unable to get access control for {0}: {1}", fileInfo.FullName, ex.Message);
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