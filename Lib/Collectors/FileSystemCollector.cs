// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.CodeAnalysis;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects Filesystem Data from the local file system.
    /// </summary>
    public class FileSystemCollector : BaseCollector
    {
        private readonly HashSet<string> roots;

        private Dictionary<string, long> sizesOnDisk = new Dictionary<string, long>();

        public static Dictionary<string, uint> ClusterSizes { get; set; } = new Dictionary<string, uint>();

        public FileSystemCollector(CollectCommandOptions opts)
        {
            this.opts = opts;
            if (opts is null)
            {
                throw new ArgumentNullException(nameof(opts));
            }

            roots = new HashSet<string>();

            if (!string.IsNullOrEmpty(opts.SelectedDirectories))
            {
                foreach (string path in opts.SelectedDirectories.Split(','))
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
            if (!roots.Any())
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
            Action<string>? IterateOnDirectory = null;
            IterateOnDirectory = Path =>
            {
                Log.Verbose("Started parsing {0}", Path);

                // To optimize calls to du on non-windows platforms we run du on the whole directory ahead of time
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var exitCode = ExternalCommandRunner.RunExternalCommand("du", Path, out string StdOut, out string StdErr);
                    if (exitCode == 0)
                    {
                        foreach (var line in StdOut.Split(Environment.NewLine))
                        {
                            var fields = line.Split('\t');
                            if (long.TryParse(fields[0], out long result))
                            {
                                sizesOnDisk[fields[1]] = result;
                            }
                        }
                    }
                }
                
                var files = Directory.EnumerateFiles(Path, "*", new System.IO.EnumerationOptions()
                {
                    IgnoreInaccessible = true
                });
                foreach (var file in files)
                {
                    StallIfHighMemoryUsageAndLowMemoryModeEnabled();
                    Log.Verbose("Started parsing {0}", file);
                    FileSystemObject obj = FilePathToFileSystemObject(file);
                    if (obj != null)
                    {
                        Results.Push(obj);

                        // TODO: Also try parse .DER as a key
                        if (Path.EndsWith(".cer", StringComparison.CurrentCulture) ||
                            Path.EndsWith(".der", StringComparison.CurrentCulture) ||
                            Path.EndsWith(".p7b", StringComparison.CurrentCulture) ||
                            Path.EndsWith(".pfx", StringComparison.CurrentCulture))
                        {
                            try
                            {
                                using var certificate = new X509Certificate2(Path);

                                var certObj = new CertificateObject(
                                    StoreLocation: StoreLocation.LocalMachine.ToString(),
                                    StoreName: StoreName.Root.ToString(),
                                    Certificate: new SerializableCertificate(certificate));

                                Results.Push(certObj);
                            }
                            catch (Exception e)
                            {
                                Log.Verbose($"Could not parse certificate from file: {file}, {e.GetType().ToString()}");
                            }
                        }
                    }
                    Log.Verbose("Finished parsing {0}", file);
                }

                Log.Verbose("Finished parsing {0}", Path);
            };

            foreach (var root in roots)
            {
                Log.Information("{0} root {1}", Strings.Get("Scanning"), root);
                var directories = Directory.EnumerateDirectories(root, "*", new System.IO.EnumerationOptions()
                {
                    ReturnSpecialDirectories = false,
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true
                });

                //First do root
                IterateOnDirectory?.Invoke(root);

                if (!opts.SingleThread == true)
                {
                    Parallel.ForEach(directories, filePath =>
                    {
                        IterateOnDirectory?.Invoke(filePath);
                    });
                }
                else
                {
                    foreach (var filePath in directories)
                    {
                        IterateOnDirectory?.Invoke(filePath);
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
        public FileSystemObject FilePathToFileSystemObject(string path)
        {
            FileSystemObject obj = new FileSystemObject(path);

            // Get Owner/Group
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var fileSecurity = new FileSecurity(path, AccessControlSections.Owner);
                    IdentityReference oid = fileSecurity.GetOwner(typeof(SecurityIdentifier));
                    obj.Owner = AsaHelpers.SidToName(oid);
                }
                catch (Exception e) {
                    Log.Verbose("Failed to get owner for {0} {1}", path, e.GetType());
                }
                try
                {
                    var fileSecurity = new FileSecurity(path, AccessControlSections.Group);
                    IdentityReference gid = fileSecurity.GetGroup(typeof(SecurityIdentifier));
                    obj.Group = AsaHelpers.SidToName(gid);
                }
                catch (Exception e) {
                    Log.Verbose("Failed to get group for {0} {1}", path, e.GetType());
                }
                try
                {
                    var fileSecurity = new FileSecurity(path, AccessControlSections.Access);
                    var rules = fileSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));
                    obj.Permissions = new Dictionary<string, string>();
                    foreach (FileSystemAccessRule? rule in rules)
                    {
                        if (rule != null)
                        {
                            string name = AsaHelpers.SidToName(rule.IdentityReference);

                            foreach (var permission in rule.FileSystemRights.ToString().Split(','))
                            {
                                if (obj.Permissions.ContainsKey(name))
                                {
                                    obj.Permissions[name] = $"{obj.Permissions[name]},{permission}";
                                }
                                else
                                {
                                    obj.Permissions.Add(name, permission);
                                }
                            }
                        }
                    }
                }
                catch (Exception e) {
                    Log.Verbose("Failed to get FileSecurity for  {1}", path, e.GetType());
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

                    obj.Permissions = new Dictionary<string, string>();
                    if (file.FileAccessPermissions.ToString().Equals("AllPermissions", StringComparison.InvariantCulture))
                    {
                        obj.Permissions.Add("User", "Read,Write,Execute");
                        obj.Permissions.Add("Group", "Read,Write,Execute");
                        obj.Permissions.Add("Other", "Read,Write,Execute");
                    }
                    else
                    {
                        var keys = new List<string>() { "User", "Group", "Other" };
                        var splits = file.FileAccessPermissions.ToString().Split(',').Select(x => x.Trim());
                        foreach (var key in keys)
                        {
                            foreach (var permission in splits.Where((x) => x.StartsWith(key, StringComparison.InvariantCulture)))
                            {
                                if (permission.Contains("ReadWriteExecute", StringComparison.InvariantCulture))
                                {
                                    obj.Permissions.Add(key, "Read,Write,Execute");
                                }
                                else
                                {
                                    if (obj.Permissions.ContainsKey(key))
                                    {
                                        obj.Permissions[key] = $"{obj.Permissions[key]},{permission.Trim().Substring(key.Length)}";
                                    }
                                    else
                                    {
                                        obj.Permissions.Add(key, permission.Trim().Substring(key.Length));
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception e) when (
                    e is ArgumentNullException
                    || e is ArgumentException
                    || e is InvalidOperationException)
                {
                    Log.Verbose("Failed to get permissions for {0} {1}", path, e.GetType().ToString());
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
                        var size = (ulong)fileInfo.Length;
                        obj.Size = size;
                        obj.SizeOnDisk = SizeOnDisk(fileInfo);

                        // This check is to try to prevent reading of cloud based files (like a dropbox folder)
                        //   and subsequently causing a download, unless the user specifically requests it with DownloadCloud.
                        if (opts.DownloadCloud == true || WindowsFileSystemUtils.IsLocal(obj.Path) || SizeOnDisk(fileInfo) > 0)
                        {
                            FileIOPermission fiop = new FileIOPermission(FileIOPermissionAccess.Read, path);
                            fiop.Demand();

                            obj.LastModified = File.GetLastWriteTimeUtc(path);
                            obj.Created = File.GetCreationTimeUtc(path);
                            
                            if (opts.GatherHashes == true)
                            {
                                obj.ContentHash = FileSystemUtils.GetFileHash(fileInfo);
                            }

                            obj.IsExecutable = FileSystemUtils.IsExecutable(obj.Path, size);

                            if (FileSystemUtils.IsWindowsExecutable(obj.Path, obj.Size))
                            {
                                obj.SignatureStatus = WindowsFileSystemUtils.GetSignatureStatus(path);
                                obj.Characteristics = WindowsFileSystemUtils.GetDllCharacteristics(path);
                            }
                            else if (FileSystemUtils.IsMacExecutable(obj.Path, obj.Size))
                            {
                                obj.MacSignatureStatus = FileSystemUtils.GetMacSignature(path);
                            }
                        }
                    }
                }
                else
                {
                    UnixSymbolicLinkInfo i = new UnixSymbolicLinkInfo(path);
                    obj.FileType = i.FileType.ToString();
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
                            if (path?.EndsWith(".app", StringComparison.InvariantCultureIgnoreCase) ?? false)
                            {
                                obj.MacSignatureStatus = FileSystemUtils.GetMacSignature(path);
                            }
                            break;
                        case FileTypes.RegularFile:
                            var fileInfo = new FileInfo(path);
                            obj.SizeOnDisk = SizeOnDisk(fileInfo);

                            if (opts.DownloadCloud || obj.SizeOnDisk > 0)
                            {
                                FileIOPermission fiop = new FileIOPermission(FileIOPermissionAccess.Read, path);
                                fiop.Demand();
                                
                                obj.LastModified = File.GetLastWriteTimeUtc(path);
                                obj.Created = File.GetCreationTimeUtc(path);

                                if (opts.GatherHashes)
                                {
                                    obj.ContentHash = FileSystemUtils.GetFileHash(path);
                                }
                                obj.IsExecutable = FileSystemUtils.IsExecutable(obj.Path, obj.Size);
                                if (FileSystemUtils.IsWindowsExecutable(obj.Path, obj.Size))
                                {
                                    obj.SignatureStatus = WindowsFileSystemUtils.GetSignatureStatus(path);
                                    obj.Characteristics = WindowsFileSystemUtils.GetDllCharacteristics(path);
                                }
                                else if (FileSystemUtils.IsMacExecutable(obj.Path, obj.Size))
                                {
                                    obj.MacSignatureStatus = FileSystemUtils.GetMacSignature(path);
                                }
                            }
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
                e is InvalidOperationException ||
                e is FileNotFoundException ||
                e is Win32Exception)
            {
                Log.Verbose("Failed to create FileInfo from File at {0} {1}", path, e.GetType().ToString());
            }
            catch (Exception e)
            {
                Log.Debug("Should be caught in DirectoryWalker {0} {1}", e.GetType().ToString(), path);
            }

            try
            {
                obj.LastModified = File.GetLastWriteTimeUtc(path);
                obj.Created = File.GetCreationTimeUtc(path);
            }
            catch (Exception e) {
                Log.Verbose("Failed to get last modified for {0} {1}", path, e.GetType());
            }

            return obj;
        }

        private long SizeOnDisk(FileInfo path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    uint clusterSize = 0;
                    var root = path.Directory.Root.FullName;
                    if (!ClusterSizes.ContainsKey(root))
                    {
                        ClusterSizes[root] = 0;
                        NativeMethods.GetDiskFreeSpace(root, out uint lpSectorsPerCluster, out uint lpBytesPerSector, out _, out _);
                        ClusterSizes[root] = lpSectorsPerCluster * lpBytesPerSector;
                    }
                    clusterSize = ClusterSizes[root];

                    if (clusterSize > 0)
                    {
                        uint lowSize = NativeMethods.GetCompressedFileSizeW(path.FullName, out uint highSize);
                        long size = (long)highSize << 32 | lowSize;
                        return ((size + clusterSize - 1) / clusterSize) * clusterSize;
                    }
                }
                catch(Exception e)
                {
                    Log.Debug("Failed to GetDiskFreeSpace for {0} ({1}:{2})", path.FullName, e.GetType(), e.Message);
                }
                return -1;
            }
            else
            {
                if (sizesOnDisk.ContainsKey(path.FullName))
                {
                    return sizesOnDisk[path.FullName];
                }
                var exitCode = ExternalCommandRunner.RunExternalCommand("du", path.FullName, out string StdOut, out string StdErr);
                if (exitCode == 0 && long.TryParse(StdOut.Split('\t')[0], out long result))
                {
                    return result;
                }
                else
                {
                    return -1;
                }
            }
        }
    }
}
