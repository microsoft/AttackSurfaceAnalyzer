// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using Serilog;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Helpers
    {
        public static string HexStringToAscii(string hex)
        {
            try
            {
                string ascii = string.Empty;

                for (int i = 0; i < hex.Length; i += 2)
                {
                    var hs = hex.Substring(i, 2);
                    uint decval = System.Convert.ToUInt32(hs, 16);
                    char character = System.Convert.ToChar(decval);
                    ascii += character;
                }

                return ascii;
            }
            catch (Exception)
            {
                Log.Debug("Couldn't convert hex string {0} to ascii", hex);
            }

            return string.Empty;
        }
        public static void OpenBrowser(string url)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Process.Start(new ProcessStartInfo("cmd", $"/c start {url}"));
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start("xdg-open", url);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Process.Start("open", url);
            }
        }

        public static bool IsAdmin()
        {
            return Elevation.IsAdministrator() || Elevation.IsRunningAsRoot();
        }

        public static string MakeValidFileName(string name)
        {
            string invalidChars = System.Text.RegularExpressions.Regex.Escape(new string(System.IO.Path.GetInvalidFileNameChars()));
            string invalidRegStr = string.Format(@"([{0}]*\.+$)|([{0}]+)", invalidChars);

            return System.Text.RegularExpressions.Regex.Replace(name, invalidRegStr, "_");
        }

        public static string GetVersionString()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            FileVersionInfo fileVersionInfo = FileVersionInfo.GetVersionInfo(assembly.Location);
            return fileVersionInfo.ProductVersion;
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

        public static string GetOsVersion()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return System.Environment.OSVersion.VersionString;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return ExternalCommandRunner.RunExternalCommand("uname", "-r");
            }
            return "";
        }

        public static string GetOsName()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return Helpers.GetPlatformString();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return ExternalCommandRunner.RunExternalCommand("uname", "-s");
            }
            return "";
        }

        public static Dictionary<string, string> GenerateMetadata()
        {
            var dict = new Dictionary<string, string>();

            dict["compare-version"] = GetVersionString();
            dict["compare-os"] = GetOsName();
            dict["compare-osversion"] = GetOsVersion();

            return dict;
        }

        public static string RunIdsToCompareId(string firstRunId, string secondRunId)
        {
            return string.Format("{0} & {1}", firstRunId, secondRunId);
        }

        public static bool IsList(object o)
        {
            if (o == null) return false;
            return o is IList &&
                   o.GetType().IsGenericType &&
                   o.GetType().GetGenericTypeDefinition().IsAssignableFrom(typeof(List<>));
        }

        public static bool IsDictionary(object o)
        {
            if (o == null) return false;
            return o is IDictionary &&
                   o.GetType().IsGenericType &&
                   o.GetType().GetGenericTypeDefinition().IsAssignableFrom(typeof(Dictionary<,>));
        }
    }
}
