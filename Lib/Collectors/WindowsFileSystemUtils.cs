// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using PeNet;
using PeNet.Header.Authenticode;
using PeNet.Header.Pe;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    public static class WindowsFileSystemUtils
    {
        public static List<DLLCHARACTERISTICS> GetDllCharacteristics(string Path, Stream input)
        {
            List<DLLCHARACTERISTICS> output = new List<DLLCHARACTERISTICS>();

            try
            {
                if (PeFile.IsPeFile(input))
                {
                    var peHeader = new PeFile(input);
                    var dllCharacteristics = peHeader.ImageNtHeaders?.OptionalHeader.DllCharacteristics;
                    if (dllCharacteristics is DllCharacteristicsType chars)
                    {
                        ushort characteristics = (ushort)chars;
                        foreach (DLLCHARACTERISTICS? characteristic in Enum.GetValues(typeof(DLLCHARACTERISTICS)))
                        {
                            if (characteristic is DLLCHARACTERISTICS c)
                            {
                                if (((ushort)c & characteristics) == (ushort)c)
                                {
                                    output.Add(c);
                                }
                            }
                        }
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
                Log.Verbose("Failed to get PE Headers for {0} ({1}:{2})", Path, e.GetType(), e.Message);
            }
            catch (Exception e)
            {
                Log.Debug(e, "Failed to get PE Headers for {0} ({1}:{2})", Path, e.GetType(), e.Message);
            }

            return output;
        }

        public static List<DLLCHARACTERISTICS> GetDllCharacteristics(string Path)
        {
            List<DLLCHARACTERISTICS> output = new List<DLLCHARACTERISTICS>();

            if (NeedsSignature(Path))
            {
                try
                {
                    if (PeFile.IsPeFile(Path))
                    {
                        using var mmf = new PeNet.FileParser.MMFile(Path);
                        var peHeader = new PeFile(mmf);
                        var dllCharacteristics = peHeader.ImageNtHeaders?.OptionalHeader.DllCharacteristics;
                        if (dllCharacteristics is DllCharacteristicsType chars)
                        {
                            ushort characteristics = (ushort)chars;
                            foreach (DLLCHARACTERISTICS? characteristic in Enum.GetValues(typeof(DLLCHARACTERISTICS)))
                            {
                                if (characteristic is DLLCHARACTERISTICS c)
                                {
                                    if (((ushort)c & characteristics) == (ushort)c)
                                    {
                                        output.Add(c);
                                    }
                                }
                            }
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
                    Log.Verbose("Failed to get PE Headers for {0} ({1}:{2})", Path, e.GetType(), e.Message);
                }
                catch (Exception e)
                {
                    Log.Debug(e, "Failed to get PE Headers for {0} ({1}:{2})", Path, e.GetType(), e.Message);
                }
            }

            return output;
        }

        public static Signature? GetSignatureStatus(string Path, Stream stream)
        {
            if (stream is null)
            {
                return null;
            }
            try
            {
                if (PeFile.IsPeFile(stream))
                {
                    var peHeader = new PeFile(stream);
                    if (peHeader.Authenticode is AuthenticodeInfo ai)
                    {
                        var sig = new Signature(ai);
                        return sig;
                    }
                }
            }
            catch (Exception e)
            {
                Log.Verbose("Failed to get signature for {0} ({1}:{2})", Path, e.GetType(), e.Message);
            }
            return null;
        }

        public static Signature? GetSignatureStatus(string Path)
        {
            if (Path is null)
            {
                return null;
            }
            try
            {
                if (PeFile.IsPeFile(Path))
                {
                    using var mmf = new PeNet.FileParser.MMFile(Path);
                    var peHeader = new PeFile(mmf);
                    if (peHeader.Authenticode is AuthenticodeInfo ai)
                    {
                        var sig = new Signature(ai);
                        return sig;
                    }
                }
            }
            catch (Exception e)
            {
                Log.Verbose("Failed to get signature for {0} ({1}:{2})", Path, e.GetType(), e.Message);
            }
            return null;
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

        public static bool NeedsSignature(string Path)
        {
            if (Path is null || !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return false;
            }
            try
            {
                FileInfo file = new FileInfo(Path);
                return FileSystemUtils.GetExecutableType(Path) == EXECUTABLE_TYPE.WINDOWS;
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
        }
    }
}