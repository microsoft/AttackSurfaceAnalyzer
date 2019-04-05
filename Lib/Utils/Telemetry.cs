using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Data.Sqlite;

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
            TelemetryConfiguration.Active.InstrumentationKey = (Gui)? TelemetryConfig.IntrumentationKeyGui : TelemetryConfig.InstrumentationKeyCli;
            Client =  new TelemetryClient();
            Client.Context.Component.Version = Helpers.GetVersionString();
            // Force some values to static values to prevent gathering unneeded data
            Client.Context.Cloud.RoleInstance = (Gui) ? "GUI" : "CLI";
            Client.Context.Cloud.RoleName = (Gui) ? "GUI" : "CLI";
            Client.Context.Location.Ip = "1.2.3.4";
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
    }
}
