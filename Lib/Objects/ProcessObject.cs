// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class ProcessObject : CollectObject
    {
        public ProcessObject(int Id, string ProcessName)
        {
            this.Id = Id;
            this.ProcessName = ProcessName;
            ResultType = Types.RESULT_TYPE.PROCESS;
        }

        public int BasePriority { get; set; }

        public bool HasExited { get; set; }

        public int Id { get; }

        /// <summary>
        ///     The identity of a ProcessObject is just the PID.
        /// </summary>
        public override string Identity
        {
            get
            {
                return $"{Id}:{ProcessName}";
            }
        }

        public ProcessModuleObject? MainModule { get; set; }

        public List<ProcessModuleObject> Modules { get; set; } = new List<ProcessModuleObject>();

        public ProcessPriorityClass PriorityClass { get; set; }

        public string ProcessName { get; set; }

        public DateTime StartTime { get; set; }

        public static ProcessObject? FromProcess(Process process)
        {
            if (process == null) return null;
            var obj = new ProcessObject(process.Id, process.ProcessName);

            try
            {
                obj.BasePriority = process.BasePriority;
            }
            catch (Exception e)
            {
                Log.Verbose($"Failed to fetch BasePriority from {obj.ProcessName} ({e.GetType()}:{e.Message})");
            }

            try
            {
                obj.PriorityClass = process.PriorityClass;
            }
            catch (Exception e)
            {
                Log.Verbose($"Failed to fetch PriorityClass from {obj.ProcessName} ({e.GetType()}:{e.Message})");
            }

            try
            {
                obj.StartTime = process.StartTime;
            }
            catch (Exception e)
            {
                Log.Verbose($"Failed to fetch StartTime from {obj.ProcessName} ({e.GetType()}:{e.Message})");
            }

            try
            {
                obj.HasExited = process.HasExited;
            }
            catch (Exception e)
            {
                Log.Verbose($"Failed to fetch HasExited from {obj.ProcessName} ({e.GetType()}:{e.Message})");
            }

            try
            {
                obj.Modules = ProcessModuleObject.FromProcessModuleCollection(process.Modules);
            }
            catch (Exception e)
            {
                Log.Verbose($"Failed to fetch Modules from {obj.ProcessName} ({e.GetType()}:{e.Message})");
            }

            try
            {
                if (process.MainModule is { })
                {
                    obj.MainModule = ProcessModuleObject.FromProcessModule(process.MainModule);
                }
            }
            catch (Exception e)
            {
                Log.Verbose($"Failed to fetch MainModule from {obj.ProcessName} ({e.GetType()}:{e.Message})");
            }

            return obj;
        }
    }
}