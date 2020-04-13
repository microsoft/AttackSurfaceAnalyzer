// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class EventLogObject : CollectObject
    {
        public DateTime? Timestamp { get; set; }
        public string? Level { get; set; }
        public string? Summary { get; set; }
        public string? Process { get; set; }
        public string? Source { get; set; }
        public List<string>? Data { get; set; }
        /// <summary>
        /// The raw event text
        /// </summary>
        public string Event { get; set; }

        public EventLogObject(string Event)
        {
            this.Event = Event;
            ResultType = Types.RESULT_TYPE.LOG;
            Data = new List<string>();
        }

        /// <summary>
        /// The raw event text
        /// </summary>
        public override string Identity
        {
            get
            {
                return Event;
            }
        }
    }
}