// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using AttackSurfaceAnalyzer.ObjectTypes;
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

        private static readonly string SQL_TRUNCATE = "delete from user_account where run_id = @run_id";
        private static readonly string INSERT_SQL = "insert into user_account (run_id, row_key, account_type, caption, description, disabled, domain, full_name, install_date, local_account, lockout, name, password_changeable, password_expires, password_required, sid, uid, gid, inactive, home_directory, shell, password_storage_algorithm, properties, serialized) values (@run_id, @row_key, @account_type, @caption, @description, @disabled, @domain, @full_name, @install_date, @local_account, @lockout, @name, @password_changeable, @password_expires, @password_required, @sid, @uid, @gid, @inactive, @home_directory, @shell, @password_storage_algorithm, @properties, @serialized)";


        public UserAccountCollector(string runId, Func<UserAccountObject, bool> filter = null)
        {
            Log.Debug("Initializing a new {0} object.", this.GetType().Name);
            this.runId = runId;
            this.filter = filter;
        }

        public void Truncate(string runid)
        {
            var cmd = new SqliteCommand(SQL_TRUNCATE, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", runId);
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public void Write(UserAccountObject obj)
        {
            _numCollected++;

            var cmd = new SqliteCommand(INSERT_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", this.runId ?? "");
            cmd.Parameters.AddWithValue("@row_key", obj.RowKey);
            cmd.Parameters.AddWithValue("@account_type", obj.AccountType ?? "");
            cmd.Parameters.AddWithValue("@caption", obj.Caption ?? "");
            cmd.Parameters.AddWithValue("@description", obj.Description ?? "");
            cmd.Parameters.AddWithValue("@disabled", obj.Disabled ?? "");
            cmd.Parameters.AddWithValue("@domain", obj.Domain ?? "");
            cmd.Parameters.AddWithValue("@full_name", obj.FullName ?? "");
            cmd.Parameters.AddWithValue("@install_date", obj.InstallDate ?? "");
            cmd.Parameters.AddWithValue("@local_account", obj.LocalAccount ?? "");
            cmd.Parameters.AddWithValue("@lockout", obj.Lockout ?? "");
            cmd.Parameters.AddWithValue("@name", obj.Name ?? "");
            cmd.Parameters.AddWithValue("@password_changeable", obj.PasswordChangeable ?? "");
            cmd.Parameters.AddWithValue("@password_expires", obj.PasswordExpires ?? "");
            cmd.Parameters.AddWithValue("@password_required", obj.PasswordRequired ?? "");
            cmd.Parameters.AddWithValue("@sid", obj.SID ?? "");
            cmd.Parameters.AddWithValue("@uid", obj.UID ?? "");
            cmd.Parameters.AddWithValue("@gid", obj.GID ?? "");
            cmd.Parameters.AddWithValue("@inactive", obj.Inactive ?? "");
            cmd.Parameters.AddWithValue("@home_directory", obj.HomeDirectory ?? "");
            cmd.Parameters.AddWithValue("@shell", obj.Shell ?? "");
            cmd.Parameters.AddWithValue("@password_storage_algorithm", obj.PasswordStorageAlgorithm ?? "");
            cmd.Parameters.AddWithValue("@properties", obj.PropertiesString());
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));

            cmd.ExecuteNonQuery();
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

            Truncate(runId);

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
                    Write(obj);
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
            var runner = new ExternalCommandRunner();

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
                Write(accountDetails[username]);
            }
        }

        private void ExecuteOsX()
        {
            Log.Debug("ExecuteOsX()");

            var runner = new ExternalCommandRunner();

            // Admin user details
            var result = runner.RunExternalCommand("dscacheutil", "-q group -a name admin");

            var lines = result.Split('\n');

            // The fourth line is a list of usernames
            // Formatted like: 'users: root gabe'
            var admins = (lines[3].Split(':')[1]).Split(' ');

            // details for all users
            result = runner.RunExternalCommand("dscacheutil", "-q user");

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
                Write(accountDetails[username]);
            }
        }
    }
}