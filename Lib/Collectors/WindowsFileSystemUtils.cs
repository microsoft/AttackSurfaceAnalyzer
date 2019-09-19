// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Libs;
using AttackSurfaceAnalyzer.Types;
using Serilog;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;


namespace AttackSurfaceAnalyzer.Collectors
{
    public class WindowsFileSystemUtils
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct WIN32_FILE_ATTRIBUTE_DATA
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
        }

        public enum GET_FILEEX_INFO_LEVELS
        {
            GetFileExInfoStandard,
            GetFileExMaxInfoLevel
        }

        [StructLayout(LayoutKind.Sequential)]
        public class FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetFileAttributesEx(string lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, out WIN32_FILE_ATTRIBUTE_DATA fileData);

        protected internal static string GetSignatureStatus(string Path)
        {
            if (!NeedsSignature(Path))
            {
                return string.Empty;
            }
            string sigStatus = WinTrust.VerifyEmbeddedSignature(Path);

            return sigStatus;
        }

        protected internal static bool NeedsSignature(string Path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return FileSystemUtils.IsExecutable(Path);
            }
            return false;
        }

        protected internal static bool IsLocal(string path)
        {
            WIN32_FILE_ATTRIBUTE_DATA fileData;
            GetFileAttributesEx(path, GET_FILEEX_INFO_LEVELS.GetFileExInfoStandard, out fileData);

            if ((fileData.dwFileAttributes & (0x00040000 + 0x00400000)) == 0)
            {
                return true;
            }

            return false;
        }

        protected internal static List<string> GetDllCharacteristics(string Path)
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
                catch (IndexOutOfRangeException)
                {
                    Log.Verbose("Failed to get PE Headers for {0} (IndexOutOfRangeException)", Path);
                }
                catch (ArgumentNullException)
                {
                    Log.Verbose("Failed to get PE Headers for {0} (ArgumentNullException)", Path);
                }
                catch (Exception e)
                {
                    Log.Debug(e, "Failed to get DLL Characteristics for path: {0}", Path);
                }
            }

            return output;
        }
    }
}