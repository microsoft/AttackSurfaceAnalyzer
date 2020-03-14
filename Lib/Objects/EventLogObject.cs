// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class EventLogObject : CollectObject
    {
        public string? Timestamp { get; set; }
        public string? Level { get; set; }
        public string? Summary { get; set; }
        public string? Process { get; set; }
        public string? Source { get; set; }
        public List<string>? Data { get; set; }
        public string Event { get; set; }

        public EventLogObject(string EventIn)
        {
            Event = EventIn;
            ResultType = Types.RESULT_TYPE.LOG;
            Data = new List<string>();
        }


        public override string Identity
        {
            get
            {
                return Event;
            }
        }
    }
}