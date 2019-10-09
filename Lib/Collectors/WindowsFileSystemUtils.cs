// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;


namespace AttackSurfaceAnalyzer.Collectors
{
    public static class WindowsFileSystemUtils
    {
        public static string GetSignatureStatus(string Path)
        {
            if (!NeedsSignature(Path))
            {
                return string.Empty;
            }
            string sigStatus = NativeMethods.VerifyEmbeddedSignature(Path);

            return sigStatus;
        }

        public static bool NeedsSignature(string Path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return FileSystemUtils.IsExecutable(Path);
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
                    || e is ArgumentException)
                {
                    Log.Verbose($"Failed to get PE Headers for {Path} {e.GetType().ToString()}");
                }
            }

            return output;
        }
    }
}