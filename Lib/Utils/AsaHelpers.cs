// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Serilog;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public static class AsaHelpers
    {
        public static Dictionary<string, string> GenerateMetadata()
        {
            var dict = new Dictionary<string, string>();

            dict["compare-version"] = GetVersionString();
            dict["compare-os"] = GetOsName().Trim();
            dict["compare-osversion"] = GetOsVersion().Trim();

            return dict;
        }

        public static string GetOsName()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return AsaHelpers.GetPlatformString();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (ExternalCommandRunner.RunExternalCommand("uname", "-s", out string StdOut, out string _) == 0)
                {
                    return StdOut;
                }
            }
            return "";
        }

        public static string GetOsVersion()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return Environment.OSVersion.VersionString;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (ExternalCommandRunner.RunExternalCommand("uname", "-r", out string StdOut, out string _) == 0)
                {
                    return StdOut;
                }
            }
            return "";
        }

        public static PLATFORM GetPlatform()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return PLATFORM.LINUX;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return PLATFORM.WINDOWS;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return PLATFORM.MACOS;
            }
            return PLATFORM.UNKNOWN;
        }

        public static string GetPlatformString()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return PLATFORM.LINUX.ToString();
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return PLATFORM.WINDOWS.ToString();
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return PLATFORM.MACOS.ToString();
            }
            return PLATFORM.UNKNOWN.ToString();
        }

        public static string GetTempFolder()
        {
            var length = 10;
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var path = Path.Combine(Path.GetTempPath(), new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray()));
            while (Directory.Exists(path))
            {
                path = Path.Combine(Path.GetTempPath(), new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray()));
            }
            return path;
        }

        public static string GetVersionString()
        {
            return (Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false) as AssemblyInformationalVersionAttribute[])?[0].InformationalVersion ?? "Unknown";
        }

        public static byte[] HexStringToBytes(string hex)
        {
            try
            {
                if (hex is null) { throw new ArgumentNullException(nameof(hex)); }

                var ascii = new byte[hex.Length / 2];

                for (int i = 0; i < hex.Length; i += 2)
                {
                    var hs = hex.Substring(i, 2);
                    uint decval = System.Convert.ToUInt32(hs, 16);
                    char character = System.Convert.ToChar(decval);
                    ascii[i / 2] = (byte)character;
                }

                return ascii;
            }
            catch (Exception e) when (
                e is ArgumentException
                || e is OverflowException
                || e is NullReferenceException)
            {
                Log.Debug("Couldn't convert hex string {0} to ascii", hex);
            }
            return Array.Empty<byte>();
        }

        public static bool IsAdmin()
        {
            if (_elevated is null)
            {
                _elevated = Elevation.IsAdministrator() || Elevation.IsRunningAsRoot();
            }
            return (bool)_elevated;
        }

        public static bool IsDictionary(object o)
        {
            if (o == null) return false;
            return o is IDictionary &&
                   o.GetType().IsGenericType &&
                   o.GetType().GetGenericTypeDefinition().IsAssignableFrom(typeof(Dictionary<,>));
        }

        public static bool IsList(object o)
        {
            if (o == null) return false;
            return o is IList &&
                   o.GetType().IsGenericType &&
                   o.GetType().GetGenericTypeDefinition().IsAssignableFrom(typeof(List<>));
        }

        public static string MakeValidFileName(string name)
        {
            string invalidChars = System.Text.RegularExpressions.Regex.Escape(new string(System.IO.Path.GetInvalidFileNameChars()));
            string invalidRegStr = $"([{invalidChars}]+)";
            return System.Text.RegularExpressions.Regex.Replace(name, invalidRegStr, "_");
        }

        public static void OpenBrowser(System.Uri url)
        {
            if (url == null) { return; }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Process.Start(new ProcessStartInfo("cmd", $"/c start {url}"));
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start("xdg-open", url.ToString());
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Process.Start("open", url.ToString());
            }
        }

        public static string RunIdsToCompareId(string firstRunId, string secondRunId)
        {
            return $"{firstRunId} & {secondRunId}";
        }

        public static string SidToName(IdentityReference? SID)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string sid = SID?.Value ?? string.Empty;
                string identity = sid;

                if (SidMap.TryGetValue(sid, out string? mappedIdentity))
                {
                    if (mappedIdentity != null)
                    {
                        return mappedIdentity;
                    }
                    else
                    {
                        SidMap.TryRemove(sid, out _);
                    }
                }

                // Only map NTAccounts, https://en.wikipedia.org/wiki/Security_Identifier
                if (sid.StartsWith("S-1-5"))
                {
                    try
                    {
                        identity = SID?.Translate(typeof(NTAccount))?.Value ?? sid;
                    }
                    catch (IdentityNotMappedException) //lgtm [cs/empty-catch-block]
                    {
                    }
                }

                SidMap.TryAdd(sid, identity);

                return sid;
            }
            return string.Empty;
        }

        private static readonly Random random = new Random();
        private static readonly ConcurrentDictionary<string, string> SidMap = new ConcurrentDictionary<string, string>();
        private static bool? _elevated = null;
    }
}