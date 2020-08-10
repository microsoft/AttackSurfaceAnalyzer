// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class EventLogObject : CollectObject
    {
        public EventLogObject(string Event)
        {
            this.Event = Event;
            ResultType = Types.RESULT_TYPE.LOG;
            Data = new List<string>();
        }

        /// <summary>
        ///     Additional associated data
        /// </summary>
        public List<string>? Data { get; set; }

        /// <summary>
        ///     The raw event text
        /// </summary>
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
        public string? Level { get; set; }

        /// <summary>
        ///     The process that the event log is from.
        /// </summary>
        public string? Process { get; set; }

        /// <summary>
        ///     The Event Log source
        /// </summary>
        public string? Source { get; set; }

        /// <summary>
        ///     A summary description of the event message (availability platform dependent)
        /// </summary>
        public string? Summary { get; set; }

        /// <summary>
        ///     The recorded Timestamp in the log file
        /// </summary>
        public DateTime? Timestamp { get; set; }
    }
}