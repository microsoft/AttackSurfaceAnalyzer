// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace AttackSurfaceAnalyzer.Objects
{
    public class ProcessObject : CollectObject
    {
        public ProcessObject(int Id, string ProcessName)
        {
            this.Id = Id;
            this.ProcessName = ProcessName;
            ResultType = Types.RESULT_TYPE.PROCESS;
        }

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

        public int Id { get; }

        public int BasePriority { get; set; }

        public bool HasExited { get; set; }

        public ProcessModuleObject? MainModule { get; set; }

        public List<ProcessModuleObject> Modules { get; set; } = new List<ProcessModuleObject>();

        public ProcessPriorityClass PriorityClass { get; set; }

        public string ProcessName { get; set; }

        public DateTime StartTime { get; set; }

        public static ProcessObject? FromProcess(Process process)
        {
            if (process == null) return null;
            return new ProcessObject(process.Id, process.ProcessName)
            {
                BasePriority = process.BasePriority,
                HasExited = process.HasExited,
                MainModule = ProcessModuleObject.FromProcessModule(process.MainModule),
                Modules = ProcessModuleObject.FromProcessModuleCollection(process.Modules),
                PriorityClass = process.PriorityClass,
                StartTime = process.StartTime
            };
        }
    }
}