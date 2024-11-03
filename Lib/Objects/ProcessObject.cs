// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract(SkipConstructor = true)]
    public class ProcessObject : CollectObject
    {
        public ProcessObject(int Id, string ProcessName)
        {
            this.Id = Id;
            this.ProcessName = ProcessName;
        }

        public override RESULT_TYPE ResultType => RESULT_TYPE.PROCESS;

        [ProtoMember(1)]
        public int BasePriority { get; set; }

        [ProtoMember(2)]
        public bool HasExited { get; set; }

        [ProtoMember(3)]
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

        [ProtoMember(4)]
        public ProcessModuleObject? MainModule { get; set; }

        [ProtoMember(5)]
        public List<ProcessModuleObject> Modules { get; set; } = new List<ProcessModuleObject>();

        [ProtoMember(6)]
        public ProcessPriorityClass PriorityClass { get; set; }

        [ProtoMember(7)]
        public string ProcessName { get; set; }

        [ProtoMember(8)]
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