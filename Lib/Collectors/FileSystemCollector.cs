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
using System.Security;
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
        private bool parallel;

        public FileSystemCollector(string runId, bool enableHashing = false, string directories = "", bool downloadCloud = false, bool parallel = true)
        {
            RunId = runId;
            this.downloadCloud = downloadCloud;
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

            Action<string> IterateOn = Path =>
            {
                Log.Verbose("Started parsing {0}", Path);
                FileSystemObject obj = FilePathToFileSystemObject(Path, downloadCloud, INCLUDE_CONTENT_HASH);
                if (obj != null)
                {
                    DatabaseManager.Write(obj, RunId);
                    if (Path.EndsWith(".cer", StringComparison.CurrentCulture) ||
                        Path.EndsWith(".der", StringComparison.CurrentCulture) ||
                        Path.EndsWith(".p7b", StringComparison.CurrentCulture))
                    {
                        try
                        {
                            var certificate = X509Certificate.CreateFromCertFile(Path);
                            var certObj = new CertificateObject()
                            {
                                StoreLocation = Path,
                                StoreName = "Disk",
                                CertificateHashString = certificate.GetCertHashString(),
                                Subject = certificate.Subject,
                                Pkcs7 = certificate.Export(X509ContentType.Cert).ToString()
                            };
                            DatabaseManager.Write(certObj, RunId);
                        }
                        catch (Exception e)
                        {
                            Log.Verbose($"Could not parse certificate from file: {Path} {e.GetType()}");
                        }
                    }
                }
                Log.Verbose("Finished parsing {0}", Path);
            };

            foreach (var root in roots)
            {
                Log.Information("{0} root {1}", Strings.Get("Scanning"), root);
                var filePathEnumerable = DirectoryWalker.WalkDirectory(root);

                if (parallel)
                {
                    Parallel.ForEach(filePathEnumerable,
                                    (filePath =>
                                    {
                                        IterateOn(filePath);
                                    }));
                }
                else
                {
                    foreach (var filePath in filePathEnumerable)
                    {
                        IterateOn(filePath);
                    }
                }
            }
        }

        /// <summary>
        /// Converts a FileSystemInfo into a FileSystemObject by reading in data about the file
        /// </summary>
        /// <param name="fileInfo">A reference to a file on disk.</param>
        /// <param name="downloadCloud">If the file is hosted in the cloud, the user has the option to include cloud files or not.</param>
        /// <param name="includeContentHash">If we should generate a hash of the file.</param>
        /// <returns></returns>
        public static FileSystemObject FilePathToFileSystemObject(string path, bool downloadCloud = false, bool includeContentHash = false)
        {
            if (path == null) { return null; }
            FileSystemObject obj = new FileSystemObject()
            {
                Path = path,
            };

            // Get Owner/Group
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var fileSecurity = new FileSecurity(path, AccessControlSections.All);
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
                        Log.Verbose("Couldn't find the Owner from SID {0} for file {1}", oid.ToString(), path);
                    }
                    try
                    {
                        // Translate group into the string representation.
                        obj.Group = (gid.Translate(typeof(NTAccount)) as NTAccount).Value;
                    }
                    catch (IdentityNotMappedException)
                    {
                        // This is fine. Some SIDs don't map to NT Accounts.
                        Log.Verbose("Couldn't find the Group from SID {0} for file {1}", gid.ToString(), path);
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
                    var file = new UnixSymbolicLinkInfo(path);
                    obj.Owner = file.OwnerUser.UserName;
                    obj.Group = file.OwnerGroup.GroupName;
                    obj.SetGid = file.IsSetGroup;
                    obj.SetUid = file.IsSetUser;

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
                    Log.Verbose($"Failed to get permissions for {path} {e.GetType().ToString()}");
                }
            }


            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (Directory.Exists(path))
                    {
                        var fileInfo = new DirectoryInfo(path);
                        if (fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                        {
                            obj.IsLink = true;
                            obj.Target = NativeMethods.GetFinalPathName(path);
                        }
                        else
                        {
                            obj.IsDirectory = true;
                        }
                    }
                    else
                    {
                        var fileInfo = new FileInfo(path);
                        obj.Size = (ulong)fileInfo.Length;
                        if (WindowsFileSystemUtils.IsLocal(obj.Path) || downloadCloud)
                        {
                            if (includeContentHash)
                            {
                                obj.ContentHash = FileSystemUtils.GetFileHash(fileInfo);
                            }

                            obj.IsExecutable = FileSystemUtils.IsExecutable(obj.Path, obj.Size);

                            if (obj.IsExecutable)
                            {
                                obj.SignatureStatus = WindowsFileSystemUtils.GetSignatureStatus(path);
                                obj.Characteristics.AddRange(WindowsFileSystemUtils.GetDllCharacteristics(path));
                            }
                        }
                    }
                }
                else
                {
                    UnixSymbolicLinkInfo i = new UnixSymbolicLinkInfo(path);
                    obj.fileType = i.FileType.ToString();
                    obj.Size = (ulong)i.Length;
                    obj.IsDirectory = false;
                    switch (i.FileType)
                    {
                        case FileTypes.SymbolicLink:
                            obj.IsLink = true;
                            obj.Target = i.ContentsPath;
                            break;
                        case FileTypes.Fifo:
                        case FileTypes.Socket:
                        case FileTypes.BlockDevice:
                        case FileTypes.CharacterDevice:
                        case FileTypes.Directory:
                            obj.IsDirectory = true;
                            break;
                        case FileTypes.RegularFile:
                            if (includeContentHash)
                            {
                                obj.ContentHash = FileSystemUtils.GetFileHash(path);
                            }
                            obj.IsExecutable = FileSystemUtils.IsExecutable(obj.Path, obj.Size);
                            break;
                    }
                }
            }
            catch (Exception e) when (
                e is ArgumentNullException ||
                e is SecurityException ||
                e is ArgumentException ||
                e is UnauthorizedAccessException ||
                e is PathTooLongException ||
                e is NotSupportedException ||
                e is InvalidOperationException)
            {
                Log.Verbose("Failed to create FileInfo from File at {0} {1}", path, e.GetType().ToString());
            }
            catch (Exception e)
            {
                Log.Debug("Should be caught in DirectoryWalker {0}", e.GetType().ToString());
            }
            return obj;
        }
    }
}
