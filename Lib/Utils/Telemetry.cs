using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Text;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Data.Sqlite;
using Microsoft.ApplicationInsights.DataContracts;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Telemetry
    {
        private static readonly string UPDATE_TELEMETRY = "replace into persisted_settings values ('telemetry_opt_out',@TelemetryOptOut)"; //lgtm [cs/literal-as-local]
        private static readonly string CHECK_TELEMETRY = "select value from persisted_settings where setting='telemetry_opt_out'";


        public static TelemetryClient Client;

        public static void Setup(bool Gui)
        {
            using (var cmd = new SqliteCommand(CHECK_TELEMETRY, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        TelemetryConfiguration.Active.DisableTelemetry = bool.Parse(reader["value"].ToString());
                    }
                }
            }
            TelemetryConfiguration.Active.InstrumentationKey = "719e5a56-dae8-425f-be07-877db7ae4d3b";
            Client =  new TelemetryClient();
            Client.Context.Component.Version = Helpers.GetVersionString();
            // Force some values to static values to prevent gathering unneeded data
            Client.Context.Cloud.RoleInstance = (Gui) ? "GUI" : "CLI";
            Client.Context.Cloud.RoleName = (Gui) ? "GUI" : "CLI";
            Client.Context.Location.Ip = "1.1.1.1";
        }

        public static void Flush()
        {
            Client.Flush();
        }

        public static void SetOptOut(bool OptOut)
        {
            TelemetryConfiguration.Active.DisableTelemetry = OptOut;
            using (var cmd = new SqliteCommand(UPDATE_TELEMETRY, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@TelemetryOptOut", OptOut.ToString());
                cmd.ExecuteNonQuery();
                DatabaseManager.Commit();
            }
        }

        public static void TrackEvent(string name, Dictionary<string,string> evt)
        {
            evt.Add("Version", Helpers.GetVersionString());
            evt.Add("OS", Helpers.GetOsName());
            evt.Add("OS_Version", Helpers.GetOsVersion());
            evt.Add("Method", new System.Diagnostics.StackFrame(1).GetMethod().Name);
            Client.TrackEvent(name, evt);
        }

        public static void TrackTrace(SeverityLevel severityLevel, Exception e)
        {
            var evt = new Dictionary<string, string>();
            evt.Add("Version", Helpers.GetVersionString());
            evt.Add("OS", Helpers.GetOsName());
            evt.Add("OS_Version", Helpers.GetOsVersion());
            evt.Add("Method", new System.Diagnostics.StackFrame(1).GetMethod().Name);
            evt.Add("Stack", e.StackTrace);
            Client.TrackTrace("Exception", severityLevel, evt);
        }
    }
}
