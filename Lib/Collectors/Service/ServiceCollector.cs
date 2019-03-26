using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Collectors.Service
{
    /// <summary>
    /// Collects metadata from the local file system.
    /// </summary>
    public class ServiceCollector : BaseCollector
    {
        /// <summary>
        /// A filter supplied to this function. All files must pass this filter in order to be included.
        /// </summary>
        private Func<ServiceController, bool> filter;

        //private static readonly string CREATE_SQL = "create table if not exists win_system_service (run_id text, row_key text, service_name text, display_name text, start_type text, current_state text)";
        private static readonly string SQL_TRUNCATE = "delete from win_system_service where run_id = @run_id";
        private static readonly string INSERT_SQL = "insert into win_system_service (run_id, row_key, service_name, display_name, start_type, current_state, serialized) values (@run_id, @row_key, @service_name, @display_name, @start_type, @current_state, @serialized)";

        public ServiceCollector(string runId, Func<ServiceController, bool> filter = null)
        {
            this.runId = runId;
            this.filter = filter;
        }

        /// <summary>
        /// Determines whether the ServiceCollector can run or not.
        /// </summary>
        /// <returns>True iff the operating system is Windows.</returns>
        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        /// <summary>
        /// Writes information about a single service to the database.
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="transaction"></param>
        public void Write(ServiceObject obj)
        {
            _numCollected++;

            var cmd = new SqliteCommand(INSERT_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", this.runId);
            cmd.Parameters.AddWithValue("@row_key", obj.GetUniqueHash());
            cmd.Parameters.AddWithValue("@service_name", obj.ServiceName);
            cmd.Parameters.AddWithValue("@display_name", obj.DisplayName);
            cmd.Parameters.AddWithValue("@start_type", obj.StartType);
            cmd.Parameters.AddWithValue("@current_state", obj.CurrentState);
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));

            cmd.ExecuteNonQuery();
        }

        public void Truncate(string runid)
        {
            var cmd = new SqliteCommand(SQL_TRUNCATE, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", runId);
        }
        /// <summary>
        /// Executes the ServiceCollector (main entrypoint).
        /// </summary>
        public override void Execute()
        {
            Start();

            if (!this.CanRunOnPlatform())
            {
                Logger.Instance.Info("ServiceCollector cannot run on this platform.");
                return;
            }

            Truncate(runId);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // This gathers official "services" on Windows, but perhaps neglects other startup items
                foreach (ServiceController service in ServiceController.GetServices())
                {
                    if (this.filter != null && !this.filter(service))
                    {
                        Logger.Instance.Info("Service [{0}] did not pass filter, ignoring.", service.ToString());
                        continue;
                    }

                    var obj = new ServiceObject()
                    {
                        DisplayName = service.DisplayName,
                        ServiceName = service.ServiceName,
                        StartType = service.StartType.ToString(),
                        CurrentState = service.Status.ToString()
                    };

                    this.Write(obj);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var runner = new ExternalCommandRunner();

                // Get the user processes
                // run "launchtl dumpstate" for the super detailed view
                // However, dumpstate is difficult to parse
                var result = runner.RunExternalCommand("launchctl", "list");

                foreach (var _line in result.Split('\n'))
                {
                    // Lines are formatted like this:
                    // PID   Exit  Name
                    //1015    0   com.apple.appstoreagent
                    var _fields = _line.Split('\t');
                    if (_fields.Length < 3 || _fields[0].Contains("PID"))
                    {
                        continue;

                    }
                    var obj = new ServiceObject()
                    {
                        DisplayName = _fields[2],
                        ServiceName = _fields[2],
                        StartType = "Unknown",
                        // If we have a current PID then it is running.
                        CurrentState = (_fields[0].Equals("-"))?"Stopped":"Running"
                    };

                    this.Write(obj);
                }

                // Then get the system processes
                result = runner.RunExternalCommand("sudo", "launchctl list");

                foreach (var _line in result.Split('\n'))
                {
                    // Lines are formatted like this, with single tab separation:
                    //  PID     Exit    Name
                    //  1015    0       com.apple.appstoreagent
                    var _fields = _line.Split('\t');
                    if (_fields.Length < 3 || _fields[0].Contains("PID"))
                    {
                        continue;

                    }
                    var obj = new ServiceObject()
                    {
                        DisplayName = _fields[2],
                        ServiceName = _fields[2],
                        StartType = "Unknown",
                        // If we have a current PID then it is running.
                        CurrentState = (_fields[0].Equals("-")) ? "Stopped" : "Running"
                    };

                    this.Write(obj);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var runner = new ExternalCommandRunner();

                var result = runner.RunExternalCommand("systemctl", "list-units --type service");

                //Split lines and remove header
                var lines = result.Split('\n');
                lines.ToList().RemoveAt(0);

                foreach (var _line in lines)
                {
                    var _fields = _line.Split('\t');

                    var obj = new ServiceObject()
                    {
                        DisplayName = _fields[4],
                        ServiceName = _fields[0],
                        StartType = "Unknown",
                        CurrentState = _fields[3],
                    };

                    Write(obj);

                }
               
                // without systemd (maybe just CentOS)
                // chkconfig --list
                // look at init.d?

                // BSD
                // service -l
                // this provides very minor amount of info
            }

            Stop();
        }

        private string underscoreToCamelCase(string name)
        {
            if (string.IsNullOrEmpty(name) || !name.Contains("_"))
            {
                return name;
            }
            string[] array = name.Split('_');
            for (int i = 0; i < array.Length; i++)
            {
                string s = array[i];
                string first = string.Empty;
                string rest = string.Empty;
                if (s.Length > 0)
                {
                    first = Char.ToUpperInvariant(s[0]).ToString();
                }
                if (s.Length > 1)
                {
                    rest = s.Substring(1).ToLowerInvariant();
                }
                array[i] = first + rest;
            }
            string newname = string.Join("", array);
            if (newname.Length > 0)
            {
                newname = Char.ToUpperInvariant(newname[0]) + newname.Substring(1);
            }
            else
            {
                newname = name;
            }
            return newname;
        }

        public void GenericCompareDatabase<T>(string tableName)
        {
            var previousRun = new HashSet<T>();
            var nextRun = new HashSet<T>();

            var cmd = new SqliteCommand("attach 'original.sqlite' as previous", DatabaseManager.Connection);
            cmd.ExecuteNonQuery();

            cmd = new SqliteCommand(string.Format("select * from previous.{0}", tableName), DatabaseManager.Connection);
            using (SqliteDataReader rdr = cmd.ExecuteReader())
            {
                while (rdr.Read())
                {
                    var obj = (T)Activator.CreateInstance(typeof(T));
                    
                    for (int i=0; i<rdr.FieldCount; i++)
                    {
                        var fieldName = rdr.GetName(i);
                        var fieldValue = rdr[i];
                        var fieldNameTitleCase = underscoreToCamelCase(fieldName);
                        try
                        {
                            Logger.Instance.Info(typeof(T));
                            var fieldInfo = typeof(T).GetField(fieldNameTitleCase, BindingFlags.Default);
                            Logger.Instance.Info(fieldInfo == null ? "NULL" : "NOT NULL");
                            if (fieldInfo.FieldType == typeof(string))
                            {
                                fieldInfo.SetValue(obj, fieldValue.ToString());
                            }
                            else
                            {
                                fieldInfo.SetValue(obj, fieldValue);
                            }
                        } catch(Exception ex)
                        {
                            Logger.Instance.Info("Unable to process field {0}: {1}", fieldNameTitleCase, ex.Message);
                        }
                    }
                    previousRun.Add(obj);
                }
            }

            cmd = new SqliteCommand(string.Format("select * from {0}", tableName), DatabaseManager.Connection);
            using (SqliteDataReader rdr = cmd.ExecuteReader())
            {
                while (rdr.Read())
                {
                    var obj = (T)Activator.CreateInstance(typeof(T));

                    for (int i = 0; i < rdr.FieldCount; i++)
                    {
                        var fieldName = rdr.GetName(i);
                        var fieldValue = rdr[i];
                        var fieldNameTitleCase = underscoreToCamelCase(fieldName);
                        var fieldInfo = typeof(T).GetField(fieldNameTitleCase, BindingFlags.Instance);
                        if (fieldInfo.FieldType == typeof(string))
                        {
                            fieldInfo.SetValue(obj, fieldValue.ToString());
                        }
                        else
                        {
                            fieldInfo.SetValue(obj, fieldValue);
                        }
                    }
                    nextRun.Add(obj);
                }
            }

            // Now everything is in an object, let's do a diff
            
            var tt = from _n in nextRun join _p in previousRun on _n.GetType().GetMethod("GetUniqueHash").Invoke(_n, new object[] { }) equals _p.GetType().GetMethod("GetUniqueHash").Invoke(_p, new object[] { }) into rr where !rr.Any() select _n;
            foreach (var _t in tt)
            {
                Logger.Instance.Info("Previous:");
                //var _q = previousRun.Where(item => item.ServiceName == _t.ServiceName).First();
                //Logger.Instance.Info(_q);
                Logger.Instance.Info("Next:");
                Logger.Instance.Info(_t);
            }
        }


        public void CompareDatabase()
        {
            var previousRun = new HashSet<ServiceObject>();
            var nextRun = new HashSet<ServiceObject>();

            var cmd = new SqliteCommand("attach 'original.sqlite' as previous", DatabaseManager.Connection);
            cmd.ExecuteNonQuery();

            // Gather initial dataset
            cmd = new SqliteCommand("select * from previous.win_system_service", DatabaseManager.Connection);
            using (SqliteDataReader rdr = cmd.ExecuteReader())
            {
                while (rdr.Read())
                {
                    var obj = new ServiceObject()
                    {
                        ServiceName = rdr["service_name"].ToString(),
                        DisplayName = rdr["display_name"].ToString(),
                        StartType = rdr["start_type"].ToString(),
                        CurrentState = rdr["current_state"].ToString()
                    };
                    var key = obj.ServiceName;

                    previousRun.Add(obj);
                }
            }

            cmd = new SqliteCommand("select * from win_system_service", DatabaseManager.Connection);
            using (SqliteDataReader rdr = cmd.ExecuteReader())
            {
                while (rdr.Read())
                {
                    var obj = new ServiceObject()
                    {
                        ServiceName = rdr["service_name"].ToString(),
                        DisplayName = rdr["display_name"].ToString(),
                        StartType = rdr["start_type"].ToString(),
                        CurrentState = rdr["current_state"].ToString()
                    };
                    var key = obj.ServiceName;

                    nextRun.Add(obj);
                }
            }

            // Now everything is in an object, let's do a diff
            var tt = from _n in nextRun join _p in previousRun on _n.GetUniqueHash() equals _p.GetUniqueHash() into rr where !rr.Any() select _n;
            foreach (var _t in tt)
            {
                Logger.Instance.Info("Previous:");
                var _q = previousRun.Where(item => item.ServiceName == _t.ServiceName).First();
                Logger.Instance.Info(_q);
                Logger.Instance.Info("Next:");
                Logger.Instance.Info(_t);
            }
        }
    }
}