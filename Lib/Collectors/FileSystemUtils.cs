// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Utils;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace AttackSurfaceAnalyzer.Collectors
{
    public static class FileSystemUtils
    {
        public static readonly List<byte[]> MacMagicNumbers = new List<byte[]>()
        {
            // 32 Bit Binary
            AsaHelpers.HexStringToBytes("FEEDFACE"),
            // 64 Bit Binary
            AsaHelpers.HexStringToBytes("FEEDFACF"),
            // 32 Bit Binary (reverse byte ordering)
            AsaHelpers.HexStringToBytes("CEFAEDFE"),
            // 64 Bit Binary (reverse byte ordering)
            AsaHelpers.HexStringToBytes("CFFAEDFE"),
            // "Fat Binary"
            AsaHelpers.HexStringToBytes("CAFEBEBE")
        };

        // ELF Format
        public static readonly byte[] ElfMagicNumber = AsaHelpers.HexStringToBytes("7F454C46");

        // MZ
        public static readonly byte[] WindowsMagicNumber = AsaHelpers.HexStringToBytes("4D5A");

        // Java classes
        public static readonly byte[] JavaMagicNumber = AsaHelpers.HexStringToBytes("CAFEBEBE");

        public static string GetFilePermissions(FileSystemInfo fileInfo)
        {
            if (fileInfo != null)
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    var filename = fileInfo.FullName;

                    FileAccessPermissions permissions = default(FileAccessPermissions);

                    if (fileInfo is FileInfo)
                    {
                        try
                        {
                            permissions = new UnixFileInfo(filename).FileAccessPermissions;
                        }
                        catch (IOException e)
                        {
                            Log.Debug("Unable to get access control for {0}: {1}", fileInfo.FullName, e.Message);
                        }
                        catch (InvalidOperationException e)
                        {
                            Log.Debug("Path probably doesn't exist: {0}", fileInfo.FullName);
                        }
                    }
                    else if (fileInfo is DirectoryInfo)
                    {
                        try
                        {
                            permissions = new UnixDirectoryInfo(filename).FileAccessPermissions;
                        }
                        catch (IOException e)
                        {
                            Log.Debug("Unable to get access control for {0}: {1}", fileInfo.FullName, e.Message);
                        }
                        catch (InvalidOperationException e)
                        {
                            Log.Debug("Path probably doesn't exist: {0}", fileInfo.FullName);
                        }
                    }
                    else
                    {
                        return "";
                    }

                    return permissions.ToString();
                }
                else
                {
                    var filename = fileInfo.FullName;
                    if (filename.Length >= 260 && !filename.StartsWith(@"\\?\"))
                    {
                        filename = $"\\?{filename}";
                    }

                    if (fileInfo is FileInfo)
                    {
                        try
                        {
                            return new FileSecurity(filename, AccessControlSections.All).GetSecurityDescriptorSddlForm(AccessControlSections.All);

                        }
                        catch (Exception e) when (
                            e is ArgumentException
                            || e is ArgumentNullException
                            || e is DirectoryNotFoundException
                            || e is FileNotFoundException
                            || e is IOException
                            || e is NotSupportedException
                            || e is PlatformNotSupportedException
                            || e is PathTooLongException
                            || e is PrivilegeNotHeldException
                            || e is SystemException
                            || e is UnauthorizedAccessException)
                        {
                            Log.Verbose($"Error parsing FileSecurity for {fileInfo.FullName} {e.GetType().ToString()}");
                        }
                    }
                    else if (fileInfo is DirectoryInfo)
                    {
                        try
                        {
                            return new DirectorySecurity(filename, AccessControlSections.All).GetSecurityDescriptorSddlForm(AccessControlSections.All);
                        }
                        catch (Exception e) when (
                            e is ArgumentException
                            || e is ArgumentNullException
                            || e is DirectoryNotFoundException
                            || e is FileNotFoundException
                            || e is IOException
                            || e is NotSupportedException
                            || e is PlatformNotSupportedException
                            || e is PathTooLongException
                            || e is PrivilegeNotHeldException
                            || e is SystemException
                            || e is UnauthorizedAccessException)
                        {
                            Log.Verbose($"Error parsing DirectorySecurity for {fileInfo.FullName} {e.GetType().ToString()}");
                        }
                    }
                    return "";
                }
            }
            return "";
        }

        public static bool IsExecutable(string Path)
        {
            if (Path is null) { return false; }

            // Shortcut to help with system files we can't read directly
            if (Path.EndsWith(".dll") || Path.EndsWith(".exe"))
            {
                return true;
            }

            byte[] fourBytes = new byte[4];
            try
            {
                using (var fileStream = File.Open(Path, FileMode.Open))
                {
                    fileStream.Read(fourBytes, 0, 4);
                }
            }
            catch (Exception e) when (
                e is ArgumentException
                || e is ArgumentNullException
                || e is PathTooLongException
                || e is DirectoryNotFoundException
                || e is IOException
                || e is UnauthorizedAccessException
                || e is ArgumentOutOfRangeException
                || e is FileNotFoundException
                || e is NotSupportedException
                || e is ObjectDisposedException)
            {
                Log.Verbose(e, $"Couldn't chomp 4 bytes of {Path}");
                return false;
            }

            return fourBytes.SequenceEqual(ElfMagicNumber) || fourBytes.SequenceEqual(JavaMagicNumber) || MacMagicNumbers.Contains(fourBytes) || fourBytes[0..2].SequenceEqual(WindowsMagicNumber);
        }

        public static string GetFileHash(FileSystemInfo fileInfo)
        {
            if (fileInfo != null)
            {
                Log.Debug("{0} {1}", Strings.Get("FileHash"), fileInfo.FullName);

                string hashValue = null;
                try
                {
                    using (var stream = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read))
                    {
                        hashValue = CryptoHelpers.CreateHash(stream);
                    }
                }
                catch (Exception e) when (
                    e is ArgumentNullException
                    || e is ArgumentException
                    || e is NotSupportedException
                    || e is FileNotFoundException
                    || e is IOException
                    || e is System.Security.SecurityException
                    || e is DirectoryNotFoundException
                    || e is UnauthorizedAccessException
                    || e is PathTooLongException
                    || e is ArgumentOutOfRangeException)
                {
                    Log.Verbose("{0}: {1} {2}", Strings.Get("Err_UnableToHash"), fileInfo.FullName, e.GetType().ToString());
                }
                return hashValue;
            }
            return string.Empty;
        }
    }
}