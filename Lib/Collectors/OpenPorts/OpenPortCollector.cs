// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using AttackSurfaceAnalyzer.ObjectTypes;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Collectors.OpenPorts
{
    public class OpenPortCollector : BaseCollector
    {

        private HashSet<string> processedObjects;

        private static readonly string SQL_INSERT = "insert into network_ports (run_id, row_key, family, address, type, port, process_name, serialized) values (@run_id, @row_key, @family, @address, @type, @port, @process_name, @serialized)";
        private static readonly string SQL_TRUNCATE = "delete from network_ports where run_id = @run_id";

        public OpenPortCollector(string runId)
        {
            Logger.Instance.Debug("Initializing a new OpenPortCollector object.");
            if (runId == null)
            {
                throw new ArgumentException("runIdentifier may not be null.");
            }
            this.runId = runId;
            this.processedObjects = new HashSet<string>();
        }

        public void Truncate(string runid)
        {
            var cmd = new SqliteCommand(SQL_TRUNCATE, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", runId);
            cmd.ExecuteNonQuery();
        }

        /**
         * Can this check run on the current platform?
         */
        public override bool CanRunOnPlatform()
        {
            try
            {
                var osRelease = File.ReadAllText("/proc/sys/kernel/osrelease") ?? "";
                osRelease = osRelease.ToLower();
                if (osRelease.Contains("microsoft") || osRelease.Contains("wsl"))
                {
                    Logger.Instance.Debug("OpenPortCollector cannot run on WSL until https://github.com/Microsoft/WSL/issues/2249 is fixed.");
                    return false;
                }
            }
            catch (Exception)
            { 
                /* OK to ignore, expecting this on non-Linux platforms. */
            };

            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public void Write(OpenPortObject obj)
        {
            _numCollected++;

            var objStr = obj.ToString();
            if (this.processedObjects.Contains(objStr))
            {
                Logger.Instance.Debug("Object already exists, ignoring: {0}", objStr);
                return;
            }

            this.processedObjects.Add(objStr);

            var cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", this.runId);
            cmd.Parameters.AddWithValue("@row_key", obj.RowKey);
            cmd.Parameters.AddWithValue("@family", obj.family);
            cmd.Parameters.AddWithValue("@address", obj.address);
            cmd.Parameters.AddWithValue("@type", obj.type);
            cmd.Parameters.AddWithValue("@port", obj.port);
            cmd.Parameters.AddWithValue("@process_name", obj.processName ?? "");
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));
            cmd.ExecuteNonQuery();
        }

        public override void Execute()
        {
            Start();
            Logger.Instance.Debug("Collecting open port information...");
            Truncate(runId);

            if (!this.CanRunOnPlatform())
            {
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
                Logger.Instance.Warn("OpenPortCollector is not available on {0}", RuntimeInformation.OSDescription);
            }
            Stop();
        }

        /// <summary>
        /// Executes the OpenPortCollector on Windows. Uses the .NET Core
        /// APIs to gather active TCP and UDP listeners and writes them 
        /// to the database.
        /// </summary>
        public void ExecuteWindows()
        {
            Logger.Instance.Debug("Collecting open port information (Windows implementation)");
            var properties = IPGlobalProperties.GetIPGlobalProperties();

            foreach (var endpoint in properties.GetActiveTcpListeners())
            {
                var obj = new OpenPortObject()
                {
                    family = endpoint.AddressFamily.ToString(),
                    address = endpoint.Address.ToString(),
                    port = endpoint.Port.ToString(),
                    type = "tcp"
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.processName = p.ProcessName;
                }

                Write(obj);
            }

            foreach (var endpoint in properties.GetActiveUdpListeners())
            {
                var obj = new OpenPortObject()
                {
                    family = endpoint.AddressFamily.ToString(),
                    address = endpoint.Address.ToString(),
                    port = endpoint.Port.ToString(),
                    type = "udp"
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.processName = p.ProcessName;
                }

                Write(obj);
            }
        }

        /// <summary>
        /// Executes the OpenPortCollector on Linux. Calls out to the `ss`
        /// command and parses the output, sending the output to the database.
        /// </summary>
        private void ExecuteLinux()
        {
            Logger.Instance.Debug("ExecuteLinux()");
            var runner = new ExternalCommandRunner();
            var result = runner.RunExternalCommand("ss", "-ln");

            foreach (var _line in result.Split('\n'))
            {
                var line = _line;
                line = line.ToLower();
                if (!line.Contains("listen"))
                {
                    continue;
                }
                var parts = Regex.Split(line, @"\s+");
                if (parts.Length <= 7)
                {
                    continue;       // Not long enough, must be an error
                }
                string address = null;
                string port = null;

                var addressMatches = Regex.Match(parts[4], @"^(.*):(\d+)$");
                if (addressMatches.Success)
                {
                    address = addressMatches.Groups[1].ToString();
                    port = addressMatches.Groups[2].ToString();

                    var obj = new OpenPortObject()
                    {
                        family = parts[0],//@TODO: Determine IPV4 vs IPv6 via looking at the address
                        address = address,
                        port = port,
                        type = parts[0]
                    };
                    Write(obj);
                }
            }
        }

        /// <summary>
        /// Executes the OpenPortCollector on OS X. Calls out to the `lsof`
        /// command and parses the output, sending the output to the database.
        /// The 'ss' command used on Linux isn't available on OS X.
        /// </summary>
        private void ExecuteOsX()
        {
            Logger.Instance.Debug("ExecuteOsX()");
            var runner = new ExternalCommandRunner();
            var result = runner.RunExternalCommand("sudo", "lsof -Pn -i4 -i6");

            foreach (var _line in result.Split('\n'))
            {
                var line = _line.ToLower();
                if (!line.Contains("listen"))
                {
                    continue; // Skip any lines which aren't open listeners
                }
                var parts = Regex.Split(line, @"\s+");
                if (parts.Length <= 9)
                {
                    continue;       // Not long enough
                }
                string address = null;
                string port = null;

                var addressMatches = Regex.Match(parts[8], @"^(.*):(\d+)$");
                if (addressMatches.Success)
                {
                    address = addressMatches.Groups[1].ToString();
                    port = addressMatches.Groups[2].ToString();

                    var obj = new OpenPortObject()
                    {
                        // Assuming family means IPv6 vs IPv4
                        family = parts[4],
                        address = address,
                        port = port,
                        type = parts[7],
                        processName = parts[0]
                    };
                    Write(obj);
                }
            }
        }

        public void Compare(string beforeKey, string afterKey)
        {
            var beforeSet = new HashSet<OpenPortObject>();
            var afterSet = new HashSet<OpenPortObject>();

            var cmd = new SqliteCommand("select * from network_ports where run_id = @before_run_id or run_id = @after_run_id", DatabaseManager.Connection);
            cmd.Parameters.AddWithValue("@before_run_id", beforeKey);
            cmd.Parameters.AddWithValue("@after_run_id", beforeKey);

            using (SqliteDataReader rdr = cmd.ExecuteReader())
            {
                while (rdr.Read())
                {
                    var runId = rdr["run_id"].ToString();
                    var obj = new OpenPortObject()
                    {
                        address = rdr["address"].ToString(),
                        family = rdr["family"].ToString(),
                        port = rdr["port"].ToString(),
                        processName = rdr["process_name"].ToString()
                    };
                    if (runId == beforeKey)
                    {
                        beforeSet.Add(obj);
                    }
                    else if (runId == afterKey)
                    {
                        afterSet.Add(obj);
                    }
                }
            }
            var newEntries = new HashSet<OpenPortObject>();
            var goneEntries = new HashSet<OpenPortObject>();

            newEntries.UnionWith(beforeSet);
            foreach (var b in beforeSet)
            {
                foreach (var a in afterSet)
                {
                    if (a.Equals(b))
                    {

                    }
                }
                if (!afterSet.Contains(b))
                {
                    Logger.Instance.Info("Open port no longer open: {0}", b.ToString());
                }
            }

            foreach (var b in afterSet)
            {
                if (!beforeSet.Contains(b))
                {
                    Logger.Instance.Info("New open port: {0}", b.ToString());
                }
            }
        }
    }
}