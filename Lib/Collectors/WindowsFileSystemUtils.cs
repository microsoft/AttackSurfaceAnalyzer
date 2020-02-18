// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using PeNet.Authenticode;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;


namespace AttackSurfaceAnalyzer.Collectors
{
    public static class WindowsFileSystemUtils
    {
        public static Signature GetSignatureStatus(string Path)
        {
            if (!NeedsSignature(Path))
            {
                return null;
            }
            try
            {
                var peHeader = new PeNet.PeFile(Path);
                var authenticodeInfo = new AuthenticodeInfo(peHeader);
                var sig = new Signature(authenticodeInfo);
                return sig;
            }
            catch(Exception)
            {
            }
            return null;
        }

        public static bool NeedsSignature(string Path)
        {
            if (Path is null)
            {
                return false;
            }
            FileInfo file;
            try
            {
                file = new FileInfo(Path);
            }
            catch (Exception e) when (
                e is FileNotFoundException ||
                e is IOException ||
                e is ArgumentNullException ||
                e is System.Security.SecurityException ||
                e is ArgumentException ||
                e is UnauthorizedAccessException ||
                e is PathTooLongException ||
                e is NotSupportedException)
            {
                return false;
            }
            return NeedsSignature(Path, (ulong)file.Length);
        }

        public static bool NeedsSignature(string Path, ulong Size)
        {
            if (Path is null)
            {
                return false;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return FileSystemUtils.IsWindowsExecutable(Path, Size);
            }
            return false;
        }

        public static bool NeedsSignature(FileSystemObject file)
        {
            if (file is null)
            {
                return false;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return FileSystemUtils.IsExecutable(file.Path, file.Size);
            }
            return false;
        }

        public static bool IsLocal(string path)
        {
            NativeMethods.WIN32_FILE_ATTRIBUTE_DATA fileData;
            NativeMethods.GetFileAttributesEx(path, NativeMethods.GET_FILEEX_INFO_LEVELS.GetFileExInfoStandard, out fileData);

            if ((fileData.dwFileAttributes & (0x00040000 + 0x00400000)) == 0)
            {
                return true;
            }

            return false;
        }

        public static List<string> GetDllCharacteristics(string Path)
        {
            List<string> output = new List<string>();

            if (NeedsSignature(Path))
            {
                try
                {
                    // This line throws the exceptions below.
                    var peHeader1 = new PeNet.PeFile(Path);
                    ushort characteristics = peHeader1.ImageNtHeaders.OptionalHeader.DllCharacteristics;
                    foreach (DLLCHARACTERISTICS characteristic in Enum.GetValues(typeof(DLLCHARACTERISTICS)))
                    {
                        if (((ushort)characteristic & characteristics) == (ushort)characteristic)
                        {
                            output.Add(characteristic.ToString());
                        }
                    }
                }
                catch (Exception e) when (
                    e is IndexOutOfRangeException
                    || e is ArgumentNullException
                    || e is System.IO.IOException
                    || e is ArgumentException
                    || e is UnauthorizedAccessException
                    || e is NullReferenceException)
                {
                    Log.Verbose($"Failed to get PE Headers for {Path} {e.GetType().ToString()}");
                }
                catch (Exception e)
                {
                    Log.Debug(e, $"Failed to get PE Headers for {Path}");
                }
            }

            return output;
        }
    }
}