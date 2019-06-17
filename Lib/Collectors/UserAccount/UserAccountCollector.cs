// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.UserAccount
{
    public class UserAccountCollector : BaseCollector
    {
        /// <summary>
        /// A filter supplied to this function. All files must pass this filter in order to be included.
        /// </summary>
        private Func<UserAccountObject, bool> filter;

        public UserAccountCollector(string runId, Func<UserAccountObject, bool> filter = null)
        {
            this.runId = runId;
            this.filter = filter;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }


        /*
         * Get Groups
         * ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Group");

ManagementObjectSearcher search = new ManagementObjectSearcher(query);

using (ManagementObjectCollection results = search.Get())

{

   foreach (ManagementObject result in results)

   {

      Log.Information(result["Name"]);

   };

};

 

Once you have the groups you can enumerate the members this way:

 


Code Block
using (ManagementObjectCollection users = result.GetRelationships("Win32_GroupUser"))

{

   foreach (ManagementObject user in users)

   {

      ManagementObject account = new ManagementObject(user["PartComponent"].ToString());

      Log.Information(" " + account["Name"]);

   };

};
*/
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
            Log.Debug("ExecuteWindows()");

            SelectQuery query = new SelectQuery("Win32_UserAccount", "LocalAccount = 'True'");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject user in searcher.Get())
            {
                var obj = new UserAccountObject();
                obj.AccountType = Convert.ToString(user["AccountType"]);
                obj.Caption = Convert.ToString(user["Caption"]);
                obj.Description = Convert.ToString(user["Description"]);
                obj.Disabled = Convert.ToString(user["Disabled"]);
                obj.Domain = Convert.ToString(user["Domain"]);
                obj.InstallDate = Convert.ToString(user["InstallDate"]);
                obj.LocalAccount = Convert.ToString(user["LocalAccount"]);
                obj.Lockout = Convert.ToString(user["Lockout"]);
                obj.Name = Convert.ToString(user["Name"]);
                obj.FullName = Convert.ToString(user["FullName"]);
                obj.PasswordChangeable = Convert.ToString(user["PasswordChangeable"]);
                obj.PasswordExpires = Convert.ToString(user["PasswordExpires"]);
                obj.PasswordRequired = Convert.ToString(user["PasswordRequired"]);
                obj.SID = Convert.ToString(user["SID"]);
                obj.Properties = null;

                if (this.filter == null || this.filter(obj))
                {
                    DatabaseManager.Write(obj, this.runId);
                }
            }
        }

        /// <summary>
        /// Executes the OpenPortCollector on Linux. Calls out to the `ss`
        /// command and parses the output, sending the output to the database.
        /// </summary>
        private void ExecuteLinux()
        {
            Log.Debug("ExecuteLinux()");
            

            var etc_passwd_lines = File.ReadAllLines("/etc/passwd");
            var etc_shadow_lines = File.ReadAllLines("/etc/shadow");

            var accountDetails = new Dictionary<string, UserAccountObject>();

            foreach (var _line in etc_passwd_lines)
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

                tempDict.UID = parts[2];
                tempDict.GID = parts[3];
                tempDict.FullName = parts[4];
                tempDict.HomeDirectory = parts[5];
                tempDict.Shell = parts[6];
                accountDetails[username] = tempDict;
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
                DatabaseManager.Write(accountDetails[username], this.runId);
            }
        }

        private void ExecuteOsX()
        {
            Log.Debug("ExecuteOsX()");

            

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
                            AccountType = (admins.Contains(value)) ? "administrator" : "standard"
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
                DatabaseManager.Write(accountDetails[username], this.runId);
            }
        }
    }
}