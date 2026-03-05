// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;
using System;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract(SkipConstructor = true)]
    public class EventLogObject : CollectObject
    {
        public EventLogObject(string Event)
        {
            this.Event = Event;
            Data = new List<string>();
        }
        public override RESULT_TYPE ResultType => RESULT_TYPE.LOG;

        /// <summary>
        ///     Additional associated data
        /// </summary>
        [ProtoMember(1)]
        public List<string>? Data { get; set; }

        /// <summary>
        ///     The raw event text
        /// </summary>
        [ProtoMember(2)]
        public string Event { get; set; }

        /// <summary>
        ///     The raw event text
        /// </summary>
        public override string Identity
        {
            get
            {
                return Event;
            }
        }

        /// <summary>
        ///     The severity level of the event message (availability platform dependent)
        /// </summary>
        [ProtoMember(3)]
        public string? Level { get; set; }

        /// <summary>
        ///     The process that the event log is from.
        /// </summary>
        [ProtoMember(4)]
        public string? Process { get; set; }

        /// <summary>
        ///     The Event Log source
        /// </summary>
        [ProtoMember(5)]
        public string? Source { get; set; }

        /// <summary>
        ///     A summary description of the event message (availability platform dependent)
        /// </summary>
        [ProtoMember(6)]
        public string? Summary { get; set; }

        /// <summary>
        ///     The recorded Timestamp in the log file
        /// </summary>
        [ProtoMember(7)]
        public DateTime? Timestamp { get; set; }
    }
}