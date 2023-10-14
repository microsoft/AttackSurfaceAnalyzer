// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    public class RegistryMonitor : BaseMonitor, IDisposable
    {
        public RegistryMonitor()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                log = new("System");
            }
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void MyOnEntryWritten(object source, EntryWrittenEventArgs e)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new PlatformNotSupportedException("ExecuteWindows is only supported on Windows platforms.");
            }
            if (e != null)
            {
                Log.Information(e.Entry.Source);
            }
        }

        public override void StartRun()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new PlatformNotSupportedException("ExecuteWindows is only supported on Windows platforms.");
            }
            if (log is { })
            {
                // backup the current auditpolicy
                ExternalCommandRunner.RunExternalCommand("auditpol", $"/backup /file:{tmpFileName}");

                // start listening to the event log
                log.EntryWritten += new EntryWrittenEventHandler(MyOnEntryWritten);
                log.EnableRaisingEvents = true;

                // Enable auditing for registry events GUID for Registry subcategory of audit policy https://msdn.microsoft.com/en-us/library/dd973928.aspx
                ExternalCommandRunner.RunExternalCommand("auditpol", "/set /subcategory:{0CCE921E-69AE-11D9-BED3-505054503030} /success:enable /failure:enable");
            }
        }

        public override void StopRun()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new PlatformNotSupportedException("ExecuteWindows is only supported on Windows platforms.");
            }
            if (log is { })
            {
                // restore the old auditpolicy
                ExternalCommandRunner.RunExternalCommand("auditpol", $"/restore /file:{tmpFileName}");

                //delete temporary file
                ExternalCommandRunner.RunExternalCommand("del", tmpFileName);

                log.EnableRaisingEvents = false;
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (log is { })
                {
                    log.Dispose();
                }
            }
        }

        private readonly EventLog? log;

        private readonly string tmpFileName = Path.GetTempFileName();
    }
}