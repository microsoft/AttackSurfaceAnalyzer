// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class RegistryMonitor : BaseMonitor
    {
        string tmpFileName = Path.GetTempFileName();
        // I believe auditpol results will go into the system log
        EventLog log = new EventLog("System");

        public RegistryMonitor()
        {
        }

        public void MyOnEntryWritten(object source, EntryWrittenEventArgs e)
        {
            Log.Information(e.Entry.Source);
        }

        public override void Start()
        {


            // backup the current auditpolicy
            ExternalCommandRunner.RunExternalCommand("auditpol", String.Format("/backup /file:{0}", tmpFileName));

            // start listening to the event log
            log.EntryWritten += new EntryWrittenEventHandler(MyOnEntryWritten);
            log.EnableRaisingEvents = true;

            // Enable auditing for registry events
            // GUID for Registry subcategory of audit policy
            // https://msdn.microsoft.com/en-us/library/dd973928.aspx
            ExternalCommandRunner.RunExternalCommand("auditpol", "/set /subcategory:{0CCE921E-69AE-11D9-BED3-505054503030} /success:enable /failure:enable");

        }

        public override void Stop()
        {


            // restore the old auditpolicy
            ExternalCommandRunner.RunExternalCommand("auditpol", String.Format("/restore /file:{0}", tmpFileName));

            //delete temporary file
            ExternalCommandRunner.RunExternalCommand("del", tmpFileName);

            log.EnableRaisingEvents = false;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }
    }
}