// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Reflection;
using AttackSurfaceAnalyzer.Objects;
using System.Collections.Generic;
using Serilog;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Helpers
    {
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

        public static string ResultTypeToTableName(RESULT_TYPE result_type)
        {
            switch (result_type)
            {
                case RESULT_TYPE.FILE:
                    return "file_system";
                case RESULT_TYPE.PORT:
                    return "network_ports";
                case RESULT_TYPE.REGISTRY:
                    return "registry";
                case RESULT_TYPE.CERTIFICATE:
                    return "certificates";
                case RESULT_TYPE.SERVICES:
                    return "win_system_service";
                case RESULT_TYPE.USER:
                    return "user_account";
                default:
                    return "null";
            }
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

        public static Dictionary<string,string> GenerateMetadata()
        {
            var dict = new Dictionary<string, string>();

            dict["version"] = GetVersionString();
            dict["os"] = GetOsName();
            dict["osversion"] = GetOsVersion();

            return dict;
        }
    }
}
