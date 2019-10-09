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
                        catch (IOException ex)
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
                        catch (IOException ex)
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
                else
                {
                    FileSystemSecurity fileSecurity = null;
                    var filename = fileInfo.FullName;
                    if (filename.Length >= 260 && !filename.StartsWith(@"\\?\"))
                    {
                        filename = $"\\?{filename}";
                    }

                    if (fileInfo is FileInfo)
                    {
                        try
                        {
                            fileSecurity = new FileSecurity(filename, AccessControlSections.All);
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
                            fileSecurity = new DirectorySecurity(filename, AccessControlSections.All);
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
                    else
                    {
                        return null;
                    }
                    if (fileSecurity != null)
                        return fileSecurity.GetSecurityDescriptorSddlForm(AccessControlSections.All);
                    else
                        return "";
                }
            }
            return "";
        }

        public static bool IsExecutable(string Path)
        {
            if (Path is null) { return false; }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                try
                {
                    var fourBytes = new byte[4];
                    using (var fileStream = File.Open(Path, FileMode.Open))
                    {
                        fileStream.Read(fourBytes, 0, 4);
                    }
                    // ELF or java
                    return fourBytes.SequenceEqual(ElfMagicNumber) || fourBytes.SequenceEqual(JavaMagicNumber);
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
                    Log.Debug(e, $"Couldn't chomp 4 bytes of {Path}");
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
                    // Mach-o format magic numbers or java class
                    return MacMagicNumbers.Contains(fourBytes) || fourBytes.SequenceEqual(JavaMagicNumber);
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
                    Log.Debug(e, $"Couldn't chomp 4 bytes of {Path}");
                    return false;
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    // We can 'trust' these file extensions to improve performance and more accurately flag system files that don't allow us to read
                    if (Path.EndsWith(".dll") || Path.EndsWith(".exe"))
                    {
                        return true;
                    }
                    var fourBytes = new byte[4];
                    using (var fileStream = File.Open(Path, FileMode.Open))
                    {
                        fileStream.Read(fourBytes, 0, 4);
                    }
                    // Windows header is 2 bytes so we just take the first two to check that    but we use all four bytes for java classes
                    return fourBytes[0..2].SequenceEqual(WindowsMagicNumber) || fourBytes.SequenceEqual(JavaMagicNumber);
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }
                catch (ArgumentNullException)
                {
                    return false;
                }
                catch (Exception e)
                {
                    Log.Debug(e, $"Couldn't chomp 4 bytes of {Path}");
                    return false;
                }
            }
            return false;
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
                catch (Exception ex)
                {
                    Log.Warning(ex, "{0}: {1} {2}", Strings.Get("Err_UnableToHash"), fileInfo.FullName, ex.Message);
                }
                return hashValue;
            }
            return string.Empty;
        }
    }
}