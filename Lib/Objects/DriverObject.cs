// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace AttackSurfaceAnalyzer.Objects
{
    public class DriverObject : CollectObject
    {
        public DriverObject(string Name)
        {
            this.Name = Name;
            ResultType = RESULT_TYPE.DRIVER;
        }

        public bool AcceptPause { get; set; }

        public bool AcceptStop { get; set; }

        public long BSS { get; set; }

        public long Code { get; set; }

        public string? Description { get; set; }

        public string? DisplayName { get; set; }

        public string? DriverType { get; set; }

        public override string Identity
        {
            get
            {
                return Name;
            }
        }

        public long Init { get; set; }
        public DateTime LinkDate { get; set; }
        public string Name { get; set; }
        public long PagedPool { get; set; }
        public string? Path { get; set; }
        public string? StartMode { get; set; }
        public string? State { get; set; }
        public string? Status { get; set; }
    }
}