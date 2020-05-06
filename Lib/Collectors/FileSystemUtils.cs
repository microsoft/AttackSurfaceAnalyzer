// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
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

                    try
                    {
                        if (fileInfo is FileInfo)
                        {
                            permissions = new UnixFileInfo(filename).FileAccessPermissions;
                        }
                        else if (fileInfo is DirectoryInfo)
                        {
                            permissions = new UnixDirectoryInfo(filename).FileAccessPermissions;
                        }
                    }
                    catch (Exception e) when (
                        e is IOException
                        || e is InvalidOperationException
                    )
                    {
                        Log.Verbose("Unable to get access control for {0}: {1}", fileInfo.FullName, e.GetType().ToString());
                    }
                    catch (Exception e)
                    {
                        Log.Debug($"Error Getting File Permissions {e.GetType().ToString()}");
                    }

                    return permissions.ToString();

                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var filename = fileInfo.FullName;
                    if (filename.Length >= 260 && !filename.StartsWith(@"\\?\"))
                    {
                        filename = $"\\?{filename}";
                    }

                    try
                    {
                        if (fileInfo is FileInfo)
                        {
                            return new FileSecurity(filename, AccessControlSections.All).GetSecurityDescriptorSddlForm(AccessControlSections.All);
                        }
                        else if (fileInfo is DirectoryInfo)
                        {
                            return new DirectorySecurity(filename, AccessControlSections.All).GetSecurityDescriptorSddlForm(AccessControlSections.All);
                        }
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
                        var InfoType = fileInfo is FileInfo ? "FileSecurity" : "DirectorySecurity";
                        Log.Verbose($"Error parsing {InfoType} for {fileInfo.FullName} {e.GetType().ToString()}");
                    }
                    catch (Exception e)
                    {
                        Log.Debug($"Error Getting File Permissions {e.GetType().ToString()}");
                    }

                    return string.Empty;
                }
            }
            return string.Empty;
        }

        public static MacSignature? GetMacSignature(string? Path)
        {
            if (ExternalCommandRunner.RunExternalCommand("codesign", $"-dv --verbose=4 {Path}", out string stdOut, out string stdErr) == 0)
            {
                var splits = stdOut.Split('\n');

                if (splits[0].EndsWith("code object is not signed at all"))
                {
                    return null;
                }

                var signature = new MacSignature(splits[0].Split(':')[1].TrimStart());
                
                foreach (var split in splits)
                {
                    var innerSplit = split.Split('=');

                    switch (innerSplit[0])
                    {
                        case "Hash Type":
                            signature.HashType = innerSplit[1].Split(' ')[0];
                            break;
                        case "Hash Choices":
                            signature.HashChoices = innerSplit[1];
                            break;
                        case "CMSDigest":
                            signature.CMSDigest = innerSplit[1];
                            break;
                        case "Authority":
                            if (signature.Authorities is null)
                            {
                                signature.Authorities = new List<string>();
                            }
                            signature.Authorities.Add(innerSplit[1]);
                            break;
                        case "Timestamp":
                            if (DateTime.TryParse(innerSplit[1], out DateTime result))
                            {
                                signature.Timestamp = result;
                            }
                            break;
                        case "TeamIdentifier":
                            signature.TeamIdentifier = innerSplit[1];
                            break;
                        default:
                            if (innerSplit[0].StartsWith("CandidateCDHashFull"))
                            {
                                signature.CandidateCDHashFull = innerSplit[1];
                            }
                            break;
                    }
                }

                return signature;
            }
            else
            {
                return null;
            }
        }

        public static bool? IsExecutable(string? Path, ulong? Size)
        {
            if (Path is null || Size is null) { return null; }
            if (Size < 4) { return false; }

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
                Log.Verbose("Couldn't chomp 4 bytes of {0} ({1})", Path, e.GetType().ToString());
                return false;
            }

            return fourBytes.SequenceEqual(ElfMagicNumber) || fourBytes.SequenceEqual(JavaMagicNumber) || MacMagicNumbers.Contains(fourBytes) || fourBytes[0..2].SequenceEqual(WindowsMagicNumber);
        }

        public static bool IsMacExecutable(string? Path, ulong? Size)
        {
            if (Path is null) { return false; }
            if (Size < 4) { return false; }

            // Shortcut to help with system files we can't read directly
            if (Path.EndsWith(".app"))
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
                Log.Verbose("Couldn't chomp 4 bytes of {0} ({1})", Path, e.GetType().ToString());
                return false;
            }

            return MacMagicNumbers.Contains(fourBytes);
        }

        public static bool IsWindowsExecutable(string? Path, ulong? Size)
        {
            if (Path is null) { return false; }
            if (Size < 4) { return false; }

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
                Log.Verbose("Couldn't chomp 4 bytes of {0} ({1})", Path, e.GetType().ToString());
                return false;
            }

            return fourBytes[0..2].SequenceEqual(WindowsMagicNumber);
        }

        public static string GetFileHash(string path)
        {
            try
            {
                return GetFileHash(new FileInfo(path)) ?? string.Empty;
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        public static string? GetFileHash(FileSystemInfo fileInfo)
        {
            if (fileInfo != null)
            {
                Log.Debug("{0} {1}", Strings.Get("FileHash"), fileInfo.FullName);

                string? hashValue = null;
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
            return null;
        }
    }
}