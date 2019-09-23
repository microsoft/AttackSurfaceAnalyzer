// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Utils;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class FileSystemUtils
    {
        private static readonly List<string> MacMagicNumbers = new List<string>()
        {
            // 32 Bit Binary
            Helpers.HexStringToAscii("FEEDFACE"),
            // 64 Bit Binary
            Helpers.HexStringToAscii("FEEDFACF"),
            // 32 Bit Binary (reverse byte ordering)
            Helpers.HexStringToAscii("CEFAEDFE"),
            // 64 Bit Binary (reverse byte ordering)
            Helpers.HexStringToAscii("CFFAEDFE"),
            // "Fat Binary"
            Helpers.HexStringToAscii("CAFEBEBE")
        };

        // ELF Format
        private static readonly string ElfMagicNumber = Helpers.HexStringToAscii("7F454C46");

        // MZ
        private static readonly string WindowsMagicNumber = Helpers.HexStringToAscii("4D5A");

        // Java classes
        private static readonly string JavaMagicNumber = Helpers.HexStringToAscii("CAFEBEBE");

        protected internal static string GetFilePermissions(FileSystemInfo fileInfo)
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
            else
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
                    return (Encoding.ASCII.GetString(fourBytes) == ElfMagicNumber);
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
                    return MacMagicNumbers.Contains(Encoding.ASCII.GetString(fourBytes));
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
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var twoBytes = new byte[2];
                    using (var fileStream = File.Open(Path, FileMode.Open))
                    {
                        fileStream.Read(twoBytes, 0, 2);
                    }
                    return (Encoding.ASCII.GetString(twoBytes) == WindowsMagicNumber);
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

        protected internal static string GetFileHash(FileSystemInfo fileInfo)
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
                Log.Warning("{0}: {1} {2}", Strings.Get("Err_UnableToHash"), fileInfo.FullName, ex.Message);
            }
            return hashValue;
        }

        public static KeyValuePair<bool, X509Certificate2> GetSignatureDetails(string path)
        {
            if (path == null)
            {
                return new KeyValuePair<bool, X509Certificate2>(false, null);
            }

            if (!File.Exists(path))
            {
                return new KeyValuePair<bool, X509Certificate2>(false, null);
            }

            X509Certificate2 certificate = null;
            try
            {
                certificate = new X509Certificate2(X509Certificate2.CreateFromSignedFile(path));
                if (!certificate.Verify())
                {
                    return new KeyValuePair<bool, X509Certificate2>(false, certificate);
                }
                if (!certificate.IssuerName.Name.Contains("Microsoft"))
                {
                    return new KeyValuePair<bool, X509Certificate2>(false, certificate);
                }
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "{0} {1}: {2}", Strings.Get("Err_ExceptionCheckSig"), path, ex.Message);
                return new KeyValuePair<bool, X509Certificate2>(false, certificate);
            }

            return new KeyValuePair<bool, X509Certificate2>(true, certificate);
        }
    }
}