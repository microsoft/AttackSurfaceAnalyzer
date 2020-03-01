// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using System;
using System.Collections.Generic;
using System.Globalization;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class AsaTelemetry
    {
        private const string INSTRUMENTATION_KEY = "719e5a56-dae8-425f-be07-877db7ae4d3b";

        private static TelemetryClient Client;
        public static bool OptOut { get; private set; }

        public static void TestMode()
        {
            Client = new TelemetryClient();
            TelemetryConfiguration.Active.DisableTelemetry = true;
        }

        public static void Setup()
        {
            if (Client == null)
            {
                using var config = TelemetryConfiguration.CreateDefault();
                OptOut = DatabaseManager.GetOptOut();
                config.InstrumentationKey = INSTRUMENTATION_KEY;
                config.DisableTelemetry = OptOut;
                Client = new TelemetryClient(config);
                Client.Context.Component.Version = AsaHelpers.GetVersionString();
                // Force some values to static values to prevent gathering unneeded data
                Client.Context.Cloud.RoleInstance = "Asa";
                Client.Context.Cloud.RoleName = "Asa";
                Client.Context.Location.Ip = "1.1.1.1";
            }
        }

        public static void Flush()
        {
            Client.Flush();
        }

        public static void SetOptOut(bool optOut)
        {
            OptOut = optOut;
            using var config = TelemetryConfiguration.CreateDefault();
            config.InstrumentationKey = INSTRUMENTATION_KEY;
            config.DisableTelemetry = OptOut;
            Client = new TelemetryClient(config);
            Client.Context.Component.Version = AsaHelpers.GetVersionString();
            // Force some values to static values to prevent gathering unneeded data
            Client.Context.Cloud.RoleInstance = "Asa";
            Client.Context.Cloud.RoleName = "Asa";
            Client.Context.Location.Ip = "1.1.1.1";
            DatabaseManager.SetOptOut(optOut);
        }

        public static void TrackEvent(string name, Dictionary<string, string> evt)
        {
            var track = (evt == null) ? new Dictionary<string, string>() : evt;
            track.Add("Version", AsaHelpers.GetVersionString());
            track.Add("OS", AsaHelpers.GetOsName());
            track.Add("OS_Version", AsaHelpers.GetOsVersion());
            track.Add("Method", new System.Diagnostics.StackFrame(1).GetMethod().Name);
            Client.TrackEvent(name, track);
        }

        public static void TrackTrace(SeverityLevel severityLevel, Exception e)
        {
            var evt = new Dictionary<string, string>();
            evt.Add("Version", AsaHelpers.GetVersionString());
            evt.Add("OS", AsaHelpers.GetOsName());
            evt.Add("OS_Version", AsaHelpers.GetOsVersion());
            evt.Add("Method", new System.Diagnostics.StackFrame(1).GetMethod().Name);
            evt.Add("Stack", (e == null) ? "" : e.StackTrace);
            Client.TrackTrace((e == null) ? "Null" : e.GetType().ToString(), severityLevel, evt);
        }
    }
}
