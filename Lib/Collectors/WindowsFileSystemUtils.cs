// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Libs;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class WindowsFileSystemUtils
    {
        public static List<string> SIGNED_EXTENSIONS = new List<string> { "dll", "exe", "cab", "ocx" };

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
            if (!WindowsFileSystemUtils.NeedsSignature(Path))
            {
                return "";
            }
            string sigStatus = WinTrust.VerifyEmbeddedSignature(Path);

            return sigStatus;
        }

        protected internal static bool NeedsSignature(string Path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var _p = Path.ToLower().Trim();
                foreach (var ext in SIGNED_EXTENSIONS)
                {
                    if (_p.EndsWith("." + ext))
                    {
                        return true;
                    }
                }
                if (IsExecutable(Path))
                {
                    return true;
                }
                return false;
            }
            else
            {
                return false;
            }
        }

        protected internal static bool IsExecutable(string filePath)
        {
            try
            {
                var twoBytes = new byte[2];
                using (var fileStream = File.Open(filePath, FileMode.Open))
                {
                    fileStream.Read(twoBytes, 0, 2);
                }
                return Encoding.UTF8.GetString(twoBytes) == "MZ";
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
            if (NeedsSignature(Path))
            {
                try
                {
                    List<string> l = new List<string>();
                    var peHeader1 = new PeNet.PeFile(Path);
                    ushort characteristics = peHeader1.ImageNtHeaders.OptionalHeader.DllCharacteristics;
                    foreach (DLLCHARACTERISTICS characteristic in Enum.GetValues(typeof(DLLCHARACTERISTICS)))
                    {
                        if (((ushort)characteristic & characteristics) == (ushort)characteristic)
                        {
                            l.Add(characteristic.ToString());
                        }
                    }
                    return l;
                }
                // Catches a case where the line establising the PeFile fails with Index outside bounds of the array.
                catch (IndexOutOfRangeException)
                {
                    Log.Verbose("Failed to get PE headers for {0}", Path);
                }
                catch (Exception e)
                {
                    Logger.DebugException(e);
                }
            }

            return new List<string>();
        }

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
                catch (UnauthorizedAccessException)
                {
                    Log.Verbose(Strings.Get("Err_AccessControl"), fileInfo.FullName);
                }
                catch (InvalidOperationException)
                {
                    Log.Verbose("Invalid operation exception {0}.", fileInfo.FullName);
                }
                catch (FileNotFoundException)
                {
                    Log.Verbose("File not found to get permissions {0}.", fileInfo.FullName);
                }
                catch (ArgumentException)
                {
                    Log.Debug("Filename not valid for getting permissions {0}", fileInfo.FullName);
                }
                catch (Exception e)
                {
                    Logger.DebugException(e);
                }
            }
            else if (fileInfo is DirectoryInfo)
            {
                try
                {
                    fileSecurity = new DirectorySecurity(filename, AccessControlSections.All);
                }
                catch (UnauthorizedAccessException)
                {
                    Log.Verbose(Strings.Get("Err_AccessControl"), fileInfo.FullName);
                }
                catch (InvalidOperationException)
                {
                    Log.Verbose("Invalid operation exception {0}.", fileInfo.FullName);
                }
                catch (Exception e)
                {
                    Logger.DebugException(e);
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
}