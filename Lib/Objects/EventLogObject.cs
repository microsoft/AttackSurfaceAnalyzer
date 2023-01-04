// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;
using MessagePack;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class EventLogObject : CollectObject
    {
        public EventLogObject(string Event)
        {
            this.Event = Event;
            Data = new List<string>();
        }
        
        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.LOG;

        /// <summary>
        ///     Additional associated data
        /// </summary>
        [Key(1)]
        public List<string>? Data { get; set; }

        /// <summary>
        ///     The raw event text
        /// </summary>
        [Key(0)]
        public string Event { get; set; }

        /// <summary>
        ///     The raw event text
        /// </summary>
        [IgnoreMember]
        public override string Identity => Event;

        /// <summary>
        ///     The severity level of the event message (availability platform dependent)
        /// </summary>
        [Key(2)]
        public string? Level { get; set; }

        /// <summary>
        ///     The process that the event log is from.
        /// </summary>
        [Key(3)]
        public string? Process { get; set; }

        /// <summary>
        ///     The Event Log source
        /// </summary>
        [Key(4)]
        public string? Source { get; set; }

        /// <summary>
        ///     A summary description of the event message (availability platform dependent)
        /// </summary>
        [Key(5)]
        public string? Summary { get; set; }

        /// <summary>
        ///     The recorded Timestamp in the log file
        /// </summary>
        [Key(6)]
        public DateTime? Timestamp { get; set; }
    }
}