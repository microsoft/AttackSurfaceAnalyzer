// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects data about the local user and group accounts.
    /// </summary>
    public class UserAccountCollector : BaseCollector
    {
        public UserAccountCollector(string runId)
        {
            this.RunId = runId;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void ExecuteInternal()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteOsX();
            }
        }

        /// <summary>
        /// Executes the UserAccountCollector on Windows. Uses WMI to gather local users.
        /// </summary>
        public void ExecuteWindows()
        {
            Dictionary<string, UserAccountObject> users = new Dictionary<string, UserAccountObject>();
            Dictionary<string, GroupAccountObject> groups = new Dictionary<string, GroupAccountObject>();
            try
            {
                List<string> lines = new List<string>(ExternalCommandRunner.RunExternalCommand("net", "localgroup").Split('\n'));

                lines.RemoveRange(0, 4);

                foreach (string line in lines)
                {
                    if (line.Contains('*'))
                    {
                        var groupName = line.Substring(1).Trim();
                        GroupAccountObject group;
                        //Get the group details
                        if (!groups.ContainsKey($"{Environment.MachineName}\\{groupName}"))
                        {
                            SelectQuery query = new SelectQuery("SELECT * FROM Win32_Group where Name='" + groupName + "' AND Domain='" + Environment.MachineName + "'");
                            using ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);

                            ManagementObject groupManagementObject = default(ManagementObject);

                            // TODO: Improve this
                            foreach (ManagementObject gmo in searcher.Get())
                            {
                                groupManagementObject = gmo;
                                break;
                            }

                            group = new GroupAccountObject()
                            {
                                Name = groupName,
                                Caption = Convert.ToString(groupManagementObject["Caption"], CultureInfo.InvariantCulture),
                                Description = Convert.ToString(groupManagementObject["Description"], CultureInfo.InvariantCulture),
                                InstallDate = Convert.ToString(groupManagementObject["InstallDate"], CultureInfo.InvariantCulture),
                                Status = Convert.ToString(groupManagementObject["Status"], CultureInfo.InvariantCulture),
                                LocalAccount = Convert.ToBoolean(groupManagementObject["LocalAccount"], CultureInfo.InvariantCulture),
                                SID = Convert.ToString(groupManagementObject["SID"], CultureInfo.InvariantCulture),
                                SIDType = Convert.ToInt32(groupManagementObject["SIDType"], CultureInfo.InvariantCulture),
                                Domain = Convert.ToString(groupManagementObject["Domain"], CultureInfo.InvariantCulture),
                            };
                        }
                        else
                        {
                            group = groups[$"{Environment.MachineName}\\{groupName}"];
                        }

                        //Get the members of the group
                        var args = $"/Node:\"{Environment.MachineName}\" path win32_groupuser where (groupcomponent=\"win32_group.name=\\\"{groupName}\\\",domain=\\\"{Environment.MachineName}\\\"\")";
                        List<string> lines_int = new List<string>(ExternalCommandRunner.RunExternalCommand("wmic", args).Split('\n'));
                        lines_int.RemoveRange(0, 1);

                        foreach (string line_int in lines_int)
                        {
                            var userName = line_int.Trim();
                            if (string.IsNullOrEmpty(userName) || !userName.Contains("Domain"))
                            {
                                continue;
                            }
                            else
                            {
                                Regex r = new Regex(@".*Win32_UserAccount.Domain=""(.*?)"",Name=""(.*?)""");

                                var domain = r.Match(userName).Groups[1].Value;
                                userName = r.Match(userName).Groups[2].Value;

                                if (string.IsNullOrEmpty(userName))
                                {
                                    continue;
                                }

                                Log.Verbose("Found {0}\\{1} as member of {2}", domain, userName, groupName);
                                if (!group.Users.Contains($"{domain}\\{userName}"))
                                {
                                    group.Users.Add($"{domain}\\{userName}");
                                }

                                var query = new SelectQuery($"SELECT * FROM Win32_UserAccount where Domain='{domain}' and Name='{userName}'");
                                using var searcher = new ManagementObjectSearcher(query);
                                foreach (ManagementObject user in searcher.Get())
                                {
                                    if (users.ContainsKey(userName))
                                    {
                                        if (!users[userName].Groups.Contains($"{domain}\\{groupName}"))
                                        {
                                            users[userName].Groups.Add(groupName);
                                        }

                                        if (groupName.Equals("Administrators"))
                                        {
                                            users[userName].Privileged = true;
                                        }
                                    }
                                    else
                                    {
                                        var obj = new UserAccountObject()
                                        {
                                            AccountType = Convert.ToString(user["AccountType"], CultureInfo.InvariantCulture),
                                            Caption = Convert.ToString(user["Caption"], CultureInfo.InvariantCulture),
                                            Description = Convert.ToString(user["Description"], CultureInfo.InvariantCulture),
                                            Disabled = Convert.ToString(user["Disabled"], CultureInfo.InvariantCulture),
                                            Domain = Convert.ToString(user["Domain"], CultureInfo.InvariantCulture),
                                            InstallDate = Convert.ToString(user["InstallDate"], CultureInfo.InvariantCulture),
                                            LocalAccount = Convert.ToString(user["LocalAccount"], CultureInfo.InvariantCulture),
                                            Lockout = Convert.ToString(user["Lockout"], CultureInfo.InvariantCulture),
                                            Name = Convert.ToString(user["Name"], CultureInfo.InvariantCulture),
                                            FullName = Convert.ToString(user["FullName"], CultureInfo.InvariantCulture),
                                            PasswordChangeable = Convert.ToString(user["PasswordChangeable"], CultureInfo.InvariantCulture),
                                            PasswordExpires = Convert.ToString(user["PasswordExpires"], CultureInfo.InvariantCulture),
                                            PasswordRequired = Convert.ToString(user["PasswordRequired"], CultureInfo.InvariantCulture),
                                            SID = Convert.ToString(user["SID"], CultureInfo.InvariantCulture),
                                            Privileged = (bool)groupName.Equals("Administrators"),
                                            Hidden = IsHiddenWindowsUser(Convert.ToString(user["Name"], CultureInfo.InvariantCulture))
                                        };
                                        obj.Groups.Add(groupName);
                                        users.Add(userName, obj);
                                    }
                                }
                            }
                            groups[$"{Environment.MachineName}\\{groupName}"] = group;
                        }
                    }
                }
            }
            catch (Exception e) when (
                e is TypeInitializationException ||
                e is PlatformNotSupportedException)
            {
                Log.Warning(Strings.Get("CollectorNotSupportedOnPlatform"), this.GetType().ToString());
            }
            catch (ExternalException)
            {
                Log.Error("Failed to run {0}", "net localgroup");
            }


            foreach (var user in users)
            {
                DatabaseManager.Write(user.Value, RunId);
            }

            foreach (var group in groups)
            {
                DatabaseManager.Write(group.Value, RunId);
            }
        }

        private bool IsHiddenWindowsUser(string username)
        {
            try
            {
                using var BaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                var SpecialAccounts = BaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList");
                if (SpecialAccounts.GetValueNames().Contains(username))
                {
                    return true;
                }
            }
            catch (Exception e) when (
                e is IOException ||
                e is ArgumentException ||
                e is UnauthorizedAccessException ||
                e is System.Security.SecurityException ||
                e is ArgumentNullException)
            {

            }
            return false;
        }

        /// <summary>
        /// Executes the User account collector on Linux. Reads /etc/passwd and /etc/shadow.
        /// </summary>
        private void ExecuteLinux()
        {
            var etc_passwd_lines = File.ReadAllLines("/etc/passwd");
            var etc_shadow_lines = File.ReadAllLines("/etc/shadow");

            Dictionary<string, GroupAccountObject> Groups = new Dictionary<string, GroupAccountObject>();

            var accountDetails = new Dictionary<string, UserAccountObject>();

            foreach (var _line in etc_passwd_lines)
            {
                var parts = _line.Split(':');

                if (!accountDetails.ContainsKey(parts[0]))
                {
                    accountDetails[parts[0]] = new UserAccountObject()
                    {
                        Name = parts[0],
                        UID = parts[2],
                        GID = parts[3],
                        FullName = parts[4],
                        HomeDirectory = parts[5],
                        Shell = parts[6]
                    };
                }
            }

            foreach (var _line in etc_shadow_lines)
            {
                var parts = _line.Split(':');
                var username = parts[0];

                if (!accountDetails.ContainsKey(username))
                {
                    accountDetails[username] = new UserAccountObject()
                    {
                        Name = username
                    };
                }
                var tempDict = accountDetails[username];

                if (parts[1].Contains("$"))
                {
                    tempDict.PasswordStorageAlgorithm = parts[1].Split('$')[1];
                }
                tempDict.PasswordExpires = parts[4];
                tempDict.Inactive = parts[6];
                tempDict.Disabled = parts[7];

                accountDetails[username] = tempDict;
            }

            foreach (var username in accountDetails.Keys)
            {
                // Admin user details
                var groupsRaw = ExternalCommandRunner.RunExternalCommand("groups", username);

                var groups = groupsRaw.Split(' ');
                foreach (var group in groups)
                {
                    if (group.Equals("sudo"))
                    {
                        accountDetails[username].Privileged = true;
                    }
                    accountDetails[username].Groups.Add(group);
                    if (Groups.ContainsKey(group))
                    {
                        Groups[group].Users.Add(username);
                    }
                    else
                    {
                        Groups[group] = new GroupAccountObject()
                        {
                            Name = group,
                        };
                        Groups[group].Users.Add(username);
                    }
                }
                DatabaseManager.Write(accountDetails[username], this.RunId);
            }
            foreach (var group in Groups)
            {
                DatabaseManager.Write(group.Value, this.RunId);
            }
        }

        /// <summary>
        /// Gathers user account details on OS X. Uses dscacheutil.
        /// </summary>
        private void ExecuteOsX()
        {
            Dictionary<string, GroupAccountObject> Groups = new Dictionary<string, GroupAccountObject>();

            // Admin user details
            var result = ExternalCommandRunner.RunExternalCommand("dscacheutil", "-q group -a name admin");

            var lines = result.Split('\n');

            // The fourth line is a list of usernames
            // Formatted like: 'users: root gabe'
            var admins = (lines[3].Split(':')[1]).Split(' ');

            // details for all users
            result = ExternalCommandRunner.RunExternalCommand("dscacheutil", "-q user");

            var accountDetails = new Dictionary<string, UserAccountObject>();

            //  We initialize a new object.  We know by the formatting of
            //  dscacheutil that we will never have a user without the name coming
            //  first
            var newUser = new UserAccountObject();
            foreach (var _line in result.Split('\n'))
            {
                var parts = _line.Split(':');
                if (parts.Length < 2)
                {
                    // There is a blank line separating each grouping of user data
                    continue;
                }
                // There is one space of padding, which we strip off here
                var value = parts[1].Substring(1);

                // dscacheutil prints the user information on multiple lines
                switch (parts[0])
                {
                    case "name":
                        accountDetails[value] = new UserAccountObject()
                        {
                            Name = value,
                            AccountType = (admins.Contains(value)) ? "administrator" : "standard",
                            Privileged = (admins.Contains(value))
                        };
                        newUser = accountDetails[value];

                        break;
                    case "password":
                        break;
                    case "uid":
                        newUser.UID = value;
                        break;
                    case "gid":
                        newUser.GID = value;
                        break;
                    case "dir":
                        newUser.HomeDirectory = value;
                        break;
                    case "shell":
                        newUser.Shell = value;
                        break;
                    case "gecos":
                        newUser.FullName = value;
                        break;
                    default:
                        break;
                }
            }
            foreach (var username in accountDetails.Keys)
            {
                // Admin user details
                string groupsRaw = string.Empty;

                try
                {
                    groupsRaw = ExternalCommandRunner.RunExternalCommand("groups", username);
                }
                catch (Exception)
                {

                }

                var groups = groupsRaw.Split(' ');
                foreach (var group in groups)
                {
                    accountDetails[username].Groups.Add(group);
                    if (Groups.ContainsKey(group))
                    {
                        Groups[group].Users.Add(username);
                    }
                    else
                    {
                        Groups[group] = new GroupAccountObject()
                        {
                            Name = group,
                        };
                        Groups[group].Users.Add(username);
                    }
                }
                accountDetails[username].Groups.AddRange(groups);
                DatabaseManager.Write(accountDetails[username], this.RunId);
            }
            foreach (var group in Groups)
            {
                DatabaseManager.Write(group.Value, this.RunId);
            }
        }
    }
}
