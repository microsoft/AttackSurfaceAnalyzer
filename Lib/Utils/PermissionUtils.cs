// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    /// <summary>
    ///     The single definition of "writable by an unprivileged user" used by the load point analysis.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         A securable object counts as user-writable when a principal that every unprivileged
    ///         interactive user belongs to is granted a right that permits planting or replacing content:
    ///     </para>
    ///     <list type="bullet">
    ///         <item><description>S-1-1-0 Everyone</description></item>
    ///         <item><description>S-1-5-4 NT AUTHORITY\INTERACTIVE</description></item>
    ///         <item><description>S-1-5-11 NT AUTHORITY\Authenticated Users</description></item>
    ///         <item><description>S-1-5-32-545 BUILTIN\Users</description></item>
    ///     </list>
    ///     <para>
    ///         Deny takes precedence over Allow, per principal. This is the canonical simplification of
    ///         Windows access evaluation; it ignores ACE ordering, which cannot change the outcome for a
    ///         canonical ACL.
    ///     </para>
    ///     <para>
    ///         Principals are matched by SID and by translated account name because <see
    ///         cref="AsaHelpers.SidToName" /> resolves S-1-5 SIDs to NTAccount form but leaves others (such
    ///         as Everyone, S-1-1-0) as raw SID strings.
    ///     </para>
    /// </remarks>
    public static class PermissionUtils
    {
        /// <summary>
        ///     Whether the principal is one every unprivileged interactive user belongs to.
        /// </summary>
        public static bool IsUnprivilegedPrincipal(string? principal)
        {
            if (string.IsNullOrWhiteSpace(principal))
            {
                return false;
            }

            var trimmed = principal.Trim();

            if (UnprivilegedPrincipals.Contains(trimmed))
            {
                return true;
            }

            // Tolerate a domain-qualified form we do not have an exact entry for.
            var separator = trimmed.LastIndexOf('\\');
            return separator >= 0 && UnprivilegedPrincipals.Contains(trimmed.Substring(separator + 1));
        }

        /// <summary>
        ///     Whether a registry right name permits writing to the key.
        /// </summary>
        public static bool IsRegistryWriteRight(string? right)
            => right is not null && RegistryWriteRights.Contains(right.Trim());

        /// <summary>
        ///     Whether a file system right name permits creating or replacing content.
        /// </summary>
        public static bool IsFileWriteRight(string? right)
            => right is not null && FileWriteRights.Contains(right.Trim());

        /// <summary>
        ///     Evaluates a live registry ACL.
        /// </summary>
        [SupportedOSPlatform("windows")]
        public static bool IsUserWritable(RegistrySecurity security)
        {
            if (security is null)
            {
                throw new ArgumentNullException(nameof(security));
            }

            return Evaluate(security.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .OfType<RegistryAccessRule>()
                .Select(rule => (
                    AsaHelpers.SidToName(rule.IdentityReference),
                    rule.AccessControlType,
                    SplitRights(rule.RegistryRights.ToString()))),
                IsRegistryWriteRight);
        }

        /// <summary>
        ///     Evaluates a live file system ACL.
        /// </summary>
        [SupportedOSPlatform("windows")]
        public static bool IsUserWritable(FileSystemSecurity security)
        {
            if (security is null)
            {
                throw new ArgumentNullException(nameof(security));
            }

            return Evaluate(security.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .OfType<FileSystemAccessRule>()
                .Select(rule => (
                    AsaHelpers.SidToName(rule.IdentityReference),
                    rule.AccessControlType,
                    SplitRights(rule.FileSystemRights.ToString()))),
                IsFileWriteRight);
        }

        /// <summary>
        ///     Evaluates the permissions stored on a collected <see cref="Objects.RegistryObject" />, which
        ///     encode the access control type as an "Allow:Right" / "Deny:Right" prefix.
        /// </summary>
        public static bool IsUserWritable(Dictionary<string, List<string>>? permissions)
        {
            if (permissions is null)
            {
                return false;
            }

            return Evaluate(permissions.SelectMany(entry => entry.Value.Select(right =>
            {
                var (type, name) = SplitAccessControlType(right);
                return (entry.Key, type, (IEnumerable<string>)new[] { name });
            })), IsRegistryWriteRight);
        }

        /// <summary>
        ///     Evaluates the permissions stored on a collected <see cref="Objects.FileSystemObject" />.
        /// </summary>
        /// <remarks>
        ///     The file system collector does not record the access control type, so every entry is treated
        ///     as an Allow. Prefer the <see cref="FileSystemSecurity" /> overload where the live ACL is
        ///     available; it honors Deny.
        /// </remarks>
        public static bool IsUserWritable(Dictionary<string, string>? permissions)
        {
            if (permissions is null)
            {
                return false;
            }

            return Evaluate(permissions.Select(entry =>
                (entry.Key, AccessControlType.Allow, SplitRights(entry.Value))), IsFileWriteRight);
        }

        /// <summary>
        ///     Walks up from <paramref name="path" /> to the closest ancestor that exists on disk. Returns
        ///     null when nothing along the chain exists.
        /// </summary>
        /// <remarks>
        ///     When a load point target is missing, the security-relevant ACL is the one on the directory
        ///     that would receive the file.
        /// </remarks>
        public static string? NearestExistingParent(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            string? current;

            try
            {
                current = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
            }
            catch (Exception)
            {
                return null;
            }

            while (!string.IsNullOrEmpty(current))
            {
                try
                {
                    if (System.IO.Directory.Exists(current))
                    {
                        return current;
                    }

                    var parent = System.IO.Path.GetDirectoryName(current);
                    if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }

                    current = parent;
                }
                catch (Exception)
                {
                    return null;
                }
            }

            return null;
        }

        /// <summary>
        ///     Splits a comma-joined combined rights mask, as produced by RegistryRights.ToString() and
        ///     FileSystemRights.ToString(), into individual right names.
        /// </summary>
        public static IEnumerable<string> SplitRights(string? rights)
            => string.IsNullOrEmpty(rights)
                ? Array.Empty<string>()
                : rights!.Split(',').Select(right => right.Trim());

        /// <summary>
        ///     Encodes an access control type and a right name into the form stored on a RegistryObject.
        /// </summary>
        public static string EncodeRight(AccessControlType type, string right) => $"{type}:{right.Trim()}";

        /// <summary>
        ///     Reverses <see cref="EncodeRight" />. Entries written before the access control type was
        ///     recorded have no prefix and are read as Allow, which is what they were assumed to be.
        /// </summary>
        public static (AccessControlType Type, string Right) SplitAccessControlType(string right)
        {
            if (right is null)
            {
                throw new ArgumentNullException(nameof(right));
            }

            var separator = right.IndexOf(':');
            if (separator > 0)
            {
                var prefix = right.Substring(0, separator);
                if (Enum.TryParse<AccessControlType>(prefix, out var type))
                {
                    return (type, right.Substring(separator + 1).Trim());
                }
            }

            return (AccessControlType.Allow, right.Trim());
        }

        private static bool Evaluate(
            IEnumerable<(string Principal, AccessControlType Type, IEnumerable<string> Rights)> aces,
            Func<string, bool> isWriteRight)
        {
            HashSet<string> allowed = new(StringComparer.OrdinalIgnoreCase);
            HashSet<string> denied = new(StringComparer.OrdinalIgnoreCase);

            foreach (var (principal, type, rights) in aces)
            {
                if (!IsUnprivilegedPrincipal(principal) || !rights.Any(isWriteRight))
                {
                    continue;
                }

                _ = type == AccessControlType.Deny ? denied.Add(principal) : allowed.Add(principal);
            }

            allowed.ExceptWith(denied);
            return allowed.Count > 0;
        }

        private static readonly HashSet<string> UnprivilegedPrincipals = new(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-1-0",
            "Everyone",
            "S-1-5-4",
            "NT AUTHORITY\\INTERACTIVE",
            "INTERACTIVE",
            "S-1-5-11",
            "NT AUTHORITY\\Authenticated Users",
            "Authenticated Users",
            "S-1-5-32-545",
            "BUILTIN\\Users",
            "Users",
        };

        /// <summary>
        ///     RegistryRights members that allow an attacker to change what a key resolves to.
        /// </summary>
        private static readonly HashSet<string> RegistryWriteRights = new(StringComparer.OrdinalIgnoreCase)
        {
            "SetValue",
            "CreateSubKey",
            "CreateLink",
            "Delete",
            "WriteKey",
            "ChangePermissions",
            "TakeOwnership",
            "FullControl",
        };

        /// <summary>
        ///     FileSystemRights members that allow an attacker to plant or replace a binary. Aliased members
        ///     that share a value (WriteData/CreateFiles, AppendData/CreateDirectories) are both listed
        ///     because which name ToString() produces is an implementation detail.
        /// </summary>
        private static readonly HashSet<string> FileWriteRights = new(StringComparer.OrdinalIgnoreCase)
        {
            "WriteData",
            "CreateFiles",
            "AppendData",
            "CreateDirectories",
            "Write",
            "Modify",
            "Delete",
            "DeleteSubdirectoriesAndFiles",
            "ChangePermissions",
            "TakeOwnership",
            "FullControl",
        };
    }
}
