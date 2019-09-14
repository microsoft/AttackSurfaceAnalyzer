// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
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
        Dictionary<string, UserAccountObject> users = new Dictionary<string, UserAccountObject>();
        Dictionary<string, GroupAccountObject> groups = new Dictionary<string, GroupAccountObject>();

        public UserAccountCollector(string runId)
        {
            this.runId = runId;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void Execute()
        {
            Start();

            if (!this.CanRunOnPlatform())
            {
                Log.Warning("UserAccountCollector is not available on {0}", RuntimeInformation.OSDescription);
                return;
            }

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
            else
            {
                Log.Warning("UserAccountCollector is not available on {0}", RuntimeInformation.OSDescription);
            }

            Stop();
        }

        /// <summary>
        /// Executes the UserAccountCollector on Windows. Uses WMI to gather local users.
        /// </summary>
        public void ExecuteWindows()
        {
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
                        if (!groups.ContainsKey(String.Format("{0}\\{1}", Environment.MachineName, groupName)))
                        {
                            SelectQuery query = new SelectQuery("SELECT * FROM Win32_Group where Name='" + groupName + "' AND Domain='" + Environment.MachineName + "'");
                            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);

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
                                Caption = Convert.ToString(groupManagementObject["Caption"]),
                                Description = Convert.ToString(groupManagementObject["Description"]),
                                InstallDate = Convert.ToString(groupManagementObject["InstallDate"]),
                                Status = Convert.ToString(groupManagementObject["Status"]),
                                LocalAccount = Convert.ToBoolean(groupManagementObject["LocalAccount"]),
                                SID = Convert.ToString(groupManagementObject["SID"]),
                                SIDType = Convert.ToInt32(groupManagementObject["SIDType"]),
                                Domain = Convert.ToString(groupManagementObject["Domain"]),
                                Users = new List<string>()
                            };
                        }
                        else
                        {
                            group = groups[String.Format("{0}\\{1}", Environment.MachineName, groupName)];
                        }

                        //Get the members of the group
                        var args = string.Format("/Node:\"{0}\" path win32_groupuser where (groupcomponent=\"win32_group.name=\\\"{1}\\\",domain=\\\"{2}\\\"\")", Environment.MachineName, groupName, Environment.MachineName);
                        List<string> lines_int = new List<string>(ExternalCommandRunner.RunExternalCommand("wmic", args).Split('\n'));
                        lines_int.RemoveRange(0, 1);

                        foreach (string line_int in lines_int)
                        {
                            var userName = line_int.Trim();
                            if (userName.Equals("") || !userName.Contains("Domain"))
                            {
                                continue;
                            }
                            else
                            {
                                Regex r = new Regex(@".*Win32_UserAccount.Domain=""(.*?)"",Name=""(.*?)""");

                                var domain = r.Match(userName).Groups[1].Value.ToString();
                                userName = r.Match(userName).Groups[2].Value.ToString();

                                if (userName.Equals(""))
                                {
                                    continue;
                                }

                                Log.Verbose("Found {0}\\{1} as member of {2}", domain, userName, groupName);
                                if (!group.Users.Contains(String.Format("{0}\\{1}", domain, userName)))
                                {
                                    group.Users.Add(String.Format("{0}\\{1}", domain, userName));
                                }

                                var query = new SelectQuery("SELECT * FROM Win32_UserAccount where Domain='" + domain + "' and Name='" + userName + "'");
                                var searcher = new ManagementObjectSearcher(query);
                                foreach (ManagementObject user in searcher.Get())
                                {
                                    if (users.ContainsKey(userName))
                                    {
                                        if (!users[userName].Groups.Contains(String.Format("{0}\\{1}", domain, groupName)))
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
                                            AccountType = Convert.ToString(user["AccountType"]),
                                            Caption = Convert.ToString(user["Caption"]),
                                            Description = Convert.ToString(user["Description"]),
                                            Disabled = Convert.ToString(user["Disabled"]),
                                            Domain = Convert.ToString(user["Domain"]),
                                            InstallDate = Convert.ToString(user["InstallDate"]),
                                            LocalAccount = Convert.ToString(user["LocalAccount"]),
                                            Lockout = Convert.ToString(user["Lockout"]),
                                            Name = Convert.ToString(user["Name"]),
                                            FullName = Convert.ToString(user["FullName"]),
                                            PasswordChangeable = Convert.ToString(user["PasswordChangeable"]),
                                            PasswordExpires = Convert.ToString(user["PasswordExpires"]),
                                            PasswordRequired = Convert.ToString(user["PasswordRequired"]),
                                            SID = Convert.ToString(user["SID"]),
                                            Privileged = (bool)groupName.Equals("Administrators"),
                                            Groups = new List<string>() { groupName }
                                        };
                                        users.Add(userName, obj);
                                    }
                                }
                            }
                            groups[String.Format("{0}\\{1}", Environment.MachineName, groupName)] = group;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logger.DebugException(e);
            }
            foreach (var user in users)
            {
                DatabaseManager.Write(user.Value, runId);
            }
            foreach (var group in groups)
            {
                DatabaseManager.Write(group.Value, runId);
            }
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

            var result = ExternalCommandRunner.RunExternalCommand("grep", "'^sudo:.*$' /etc/group | cut - d: -f4");

            foreach (var _line in result.Split('\n'))
            {
                accountDetails[_line].Privileged = true;
            }

            foreach (var username in accountDetails.Keys)
            {
                // Admin user details
                var groupsRaw = ExternalCommandRunner.RunExternalCommand("groups", "username");

                var groups = result.Split(' ');
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
                            Users = new List<string>() { username }
                        };
                    }
                }
                DatabaseManager.Write(accountDetails[username], this.runId);
            }
            foreach (var group in Groups)
            {
                DatabaseManager.Write(group.Value, this.runId);
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
                var groupsRaw = ExternalCommandRunner.RunExternalCommand("groups", "username");

                var groups = result.Split(' ');
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
                            Users = new List<string>() { username }
                        };
                    }
                }
                accountDetails[username].Groups = new List<string>(groups);
                DatabaseManager.Write(accountDetails[username], this.runId);
            }
            foreach (var group in Groups)
            {
                DatabaseManager.Write(group.Value, this.runId);
            }
        }
    }
}