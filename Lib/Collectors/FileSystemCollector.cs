// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects Filesystem Data from the local file system.
    /// </summary>
    public class FileSystemCollector : BaseCollector
    {
        private readonly HashSet<string> roots;

        private bool INCLUDE_CONTENT_HASH = false;

        private bool downloadCloud;
        private bool examineCertificates;
        private bool parallel;

        public FileSystemCollector(string runId, bool enableHashing = false, string directories = "", bool downloadCloud = false, bool examineCertificates = false, bool parallel = true)
        {
            this.RunId = runId;
            this.downloadCloud = downloadCloud;
            this.examineCertificates = examineCertificates;
            this.parallel = parallel;

            roots = new HashSet<string>();
            INCLUDE_CONTENT_HASH = enableHashing;

            if (!string.IsNullOrEmpty(directories))
            {
                foreach (string path in directories.Split(','))
                {
                    AddRoot(path);
                }
            }

        }

        /// <summary>
        /// Add a root to be collected
        /// </summary>
        /// <param name="root">The path to scan</param>
        public void AddRoot(string root)
        {
            roots.Add(root);
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void ExecuteInternal()
        {
            if (roots == null || !roots.Any())
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    foreach (var driveInfo in DriveInfo.GetDrives())
                    {
                        if (driveInfo.IsReady && driveInfo.DriveType == DriveType.Fixed)
                        {
                            roots.Add(driveInfo.Name);
                        }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    roots.Add("/");
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    roots.Add("/");
                }
            }

            Action<FileSystemInfo> IterateOn = fileInfo =>
            {
                if (fileInfo is DirectoryInfo)
                {
                    Log.Verbose("Starting Directory {0}", fileInfo.FullName);
                }
                else
                {
                    Log.Verbose("Started parsing {0}", fileInfo.FullName);
                }
                FileSystemObject obj = FileSystemInfoToFileSystemObject(fileInfo, downloadCloud, INCLUDE_CONTENT_HASH);
                if (obj != null)
                {
                    DatabaseManager.Write(obj, RunId);
                    if (examineCertificates &&
                        fileInfo.FullName.EndsWith(".cer", StringComparison.CurrentCulture) ||
                        fileInfo.FullName.EndsWith(".der", StringComparison.CurrentCulture) ||
                        fileInfo.FullName.EndsWith(".p7b", StringComparison.CurrentCulture))
                    {
                        try
                        {
                            var certificate = X509Certificate.CreateFromCertFile(fileInfo.FullName);
                            var certObj = new CertificateObject()
                            {
                                StoreLocation = fileInfo.FullName,
                                StoreName = "Disk",
                                CertificateHashString = certificate.GetCertHashString(),
                                Subject = certificate.Subject,
                                Pkcs7 = certificate.Export(X509ContentType.Cert).ToString()
                            };
                            DatabaseManager.Write(certObj, RunId);
                        }
                        catch (Exception e) when (
                            e is System.Security.Cryptography.CryptographicException
                            || e is ArgumentException)
                        {
                            Log.Verbose($"Could not parse certificate from file: {fileInfo.FullName}");
                        }
                    }
                }
                Log.Verbose("Finished parsing {0}", fileInfo.FullName);
            };

            foreach (var root in roots)
            {
                Log.Information("{0} root {1}", Strings.Get("Scanning"), root);
                var fileInfoEnumerable = DirectoryWalker.WalkDirectory(root);
                
                if (parallel)
                {
                    Parallel.ForEach(fileInfoEnumerable,
                                    (fileInfo =>
                                    {
                                        IterateOn(fileInfo);
                                    }));
                }
                else
                {
                    foreach (var fileInfo in fileInfoEnumerable)
                    {
                        IterateOn(fileInfo);
                    }
                }
            }
        }

        /// <summary>
        /// Converts a FileSystemInfo into a FileSystemObject by reading in data about the file
        /// </summary>
        /// <param name="fileInfo">A reference to a file on disk.</param>
        /// <param name="downloadCloud">If the file is hosted in the cloud, the user has the option to include cloud files or not.</param>
        /// <param name="INCLUDE_CONTENT_HASH">If we should generate a hash of the file.</param>
        /// <returns></returns>
        public static FileSystemObject FileSystemInfoToFileSystemObject(FileSystemInfo fileInfo, bool downloadCloud = false, bool INCLUDE_CONTENT_HASH = false)
        {
            if (fileInfo == null) { return null; }
            FileSystemObject obj = new FileSystemObject()
            {
                Path = fileInfo.FullName,
                PermissionsString = FileSystemUtils.GetFilePermissions(fileInfo),
            };
            // Get Owner/Group
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var fileSecurity = new FileSecurity(fileInfo.FullName, AccessControlSections.All);
                    IdentityReference oid = fileSecurity.GetOwner(typeof(SecurityIdentifier));
                    IdentityReference gid = fileSecurity.GetGroup(typeof(SecurityIdentifier));

                    // Set the Owner and Group to the SID, in case we can't properly translate
                    obj.Owner = oid.ToString();
                    obj.Group = gid.ToString();

                    try
                    {
                        // Translate owner into the string representation.
                        obj.Owner = (oid.Translate(typeof(NTAccount)) as NTAccount).Value;
                    }
                    catch (IdentityNotMappedException)
                    {
                        Log.Verbose("Couldn't find the Owner from SID {0} for file {1}", oid.ToString(), fileInfo.FullName);
                    }
                    try
                    {
                        // Translate group into the string representation.
                        obj.Group = (gid.Translate(typeof(NTAccount)) as NTAccount).Value;
                    }
                    catch (IdentityNotMappedException)
                    {
                        // This is fine. Some SIDs don't map to NT Accounts.
                        Log.Verbose("Couldn't find the Group from SID {0} for file {1}", gid.ToString(), fileInfo.FullName);
                    }

                    var rules = fileSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                    foreach (FileSystemAccessRule rule in rules)
                    {
                        string name = rule.IdentityReference.Value;

                        try
                        {
                            name = rule.IdentityReference.Translate(typeof(NTAccount)).Value;
                        }
                        catch (IdentityNotMappedException)
                        {
                            // This is fine. Some SIDs don't map to NT Accounts.
                        }

                        foreach (var permission in rule.FileSystemRights.ToString().Split(','))
                        {
                            obj.Permissions.Add(new KeyValuePair<string, string>(name, permission));
                        }

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
                    Log.Verbose($"Error instantiating FileSecurity object {obj.Path} {e.GetType().ToString()}");
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                try
                {
                    Log.Verbose("Before UnixFileInfo {0}", fileInfo.FullName);
                    var file = new UnixFileInfo(fileInfo.FullName);
                    obj.Owner = file.OwnerUser.UserName;
                    obj.Group = file.OwnerGroup.GroupName;
                    obj.SetGid = file.IsSetGroup;
                    obj.SetUid = file.IsSetUser;
                    Log.Verbose("After UnixFileInfo {0}", fileInfo.FullName);

                    if (file.FileAccessPermissions.ToString().Equals("AllPermissions", StringComparison.InvariantCulture))
                    {
                        obj.Permissions.Add(new KeyValuePair<string, string>("User", "Read"));
                        obj.Permissions.Add(new KeyValuePair<string, string>("User", "Write"));
                        obj.Permissions.Add(new KeyValuePair<string, string>("User", "Execute"));
                        obj.Permissions.Add(new KeyValuePair<string, string>("Group", "Read"));
                        obj.Permissions.Add(new KeyValuePair<string, string>("Group", "Write"));
                        obj.Permissions.Add(new KeyValuePair<string, string>("Group", "Execute"));
                        obj.Permissions.Add(new KeyValuePair<string, string>("Other", "Read"));
                        obj.Permissions.Add(new KeyValuePair<string, string>("Other", "Write"));
                        obj.Permissions.Add(new KeyValuePair<string, string>("Other", "Execute"));
                    }
                    else
                    {
                        foreach (var permission in file.FileAccessPermissions.ToString().Split(',').Where((x) => x.Trim().StartsWith("User", StringComparison.InvariantCulture)))
                        {
                            if (permission.Contains("ReadWriteExecute", StringComparison.InvariantCulture))
                            {
                                obj.Permissions.Add(new KeyValuePair<string, string>("User", "Read"));
                                obj.Permissions.Add(new KeyValuePair<string, string>("User", "Write"));
                                obj.Permissions.Add(new KeyValuePair<string, string>("User", "Execute"));
                            }
                            else
                            {
                                obj.Permissions.Add(new KeyValuePair<string, string>("User", permission.Trim().Substring(4)));
                            }
                        }
                        foreach (var permission in file.FileAccessPermissions.ToString().Split(',').Where((x) => x.Trim().StartsWith("Group", StringComparison.InvariantCulture)))
                        {
                            if (permission.Contains("ReadWriteExecute", StringComparison.InvariantCulture))
                            {
                                obj.Permissions.Add(new KeyValuePair<string, string>("Group", "Read"));
                                obj.Permissions.Add(new KeyValuePair<string, string>("Group", "Write"));
                                obj.Permissions.Add(new KeyValuePair<string, string>("Group", "Execute"));
                            }
                            else
                            {
                                obj.Permissions.Add(new KeyValuePair<string, string>("Group", permission.Trim().Substring(5)));
                            }
                        }
                        foreach (var permission in file.FileAccessPermissions.ToString().Split(',').Where((x) => x.Trim().StartsWith("Other", StringComparison.InvariantCulture)))
                        {
                            if (permission.Contains("ReadWriteExecute", StringComparison.InvariantCulture))
                            {
                                obj.Permissions.Add(new KeyValuePair<string, string>("Other", "Read"));
                                obj.Permissions.Add(new KeyValuePair<string, string>("Other", "Write"));
                                obj.Permissions.Add(new KeyValuePair<string, string>("Other", "Execute"));
                            }
                            else
                            {
                                obj.Permissions.Add(new KeyValuePair<string, string>("Other", permission.Trim().Substring(5)));
                            }
                        }
                    }
                }
                catch (Exception e) when (
                    e is ArgumentNullException
                    || e is ArgumentException
                    || e is InvalidOperationException)
                {
                    Log.Verbose($"Failed to get permissions for {fileInfo.FullName} {e.GetType().ToString()}");
                }
            }


            if (fileInfo is DirectoryInfo)
            {
                obj.IsDirectory = true;
            }
            else if (fileInfo is FileInfo)
            {
                obj.IsDirectory = false;
                try
                {
                    // This can throw if access is denied. That's fine as everything below also wouldn't work when access is denied.
                    obj.Size = (ulong)(fileInfo as FileInfo).Length;

                    if (INCLUDE_CONTENT_HASH)
                    {
                        obj.ContentHash = FileSystemUtils.GetFileHash(fileInfo);
                    }

                    // Set IsExecutable and Signature Status
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {

                        if (WindowsFileSystemUtils.IsLocal(obj.Path) || downloadCloud)
                        {

                            if (WindowsFileSystemUtils.NeedsSignature(obj))
                            {
                                obj.SignatureStatus = WindowsFileSystemUtils.GetSignatureStatus(fileInfo.FullName);
                                obj.Characteristics.AddRange(WindowsFileSystemUtils.GetDllCharacteristics(fileInfo.FullName));
                                obj.IsExecutable = FileSystemUtils.IsExecutable(obj.Path, obj.Size);
                            }
                        }

                    }
                    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        obj.IsExecutable = FileSystemUtils.IsExecutable(obj.Path, obj.Size);
                    }
                }
                catch (Exception e) when (
                    e is FileNotFoundException ||
                    e is IOException ||
                    e is UnauthorizedAccessException)
                {

                }
                catch (Exception e)
                {
                    Log.Debug("Should be catching in FileSystemInfoToFileSystemObject {0}", e.GetType().ToString());
                }
            }
            
            return obj;
        }
    }
}