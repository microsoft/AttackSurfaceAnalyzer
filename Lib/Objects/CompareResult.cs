// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using Markdig.Helpers;
using System.Collections.Generic;
using System.IO;

namespace AttackSurfaceAnalyzer.Objects
{
    

    public class CompareResult
    {
        public string Identity { get; set; }
        public CHANGE_TYPE ChangeType { get; set; }
        public RESULT_TYPE ResultType { get; set; }
        public ANALYSIS_RESULT_TYPE Analysis { get; set; }
        public List<Rule> Rules { get; set; } = new List<Rule>();
        public List<Diff> Diffs { get; set; } = new List<Diff>();
        public string? BaseRowKey { get; set; }
        public string? CompareRowKey { get; set; }
        public string? BaseRunId { get; set; }
        public string? CompareRunId { get; set; }
        public object? Base { get; set; }
        public object? Compare { get; set; }

        public bool ShouldSerializeDiffs()
        {
            return Diffs?.Count > 0;
        }

        public bool ShouldSerializeRules()
        {
            return Rules?.Count > 0;
        }

        public CompareResult(string IdentityIn)
        {
            Identity = IdentityIn;
        }
    }

    public class OutputFileMonitorResult
    {
        public string? RowKey { get; set; }
        public string? Timestamp { get; set; }
        public string? OldPath { get; set; }
        public string Path { get; set; }
        public string? OldName { get; set; }
        public string? Name { get; set; }
        public CHANGE_TYPE ChangeType { get; set; }

        public OutputFileMonitorResult(string PathIn)
        {
            Path = PathIn;
        }
    }

    public class OutputCompareResult : CompareResult
    {
        public string? SerializedBase { get; set; }
        public string? SerializedCompare { get; set; }

        public OutputCompareResult(string IdentityIn) : base(IdentityIn) { }
    }

    public class FileSystemMonitorResult
    {
        public FileSystemEventArgs evt { get; set; }
        public NotifyFilters filter { get; set; }

        public FileSystemMonitorResult(FileSystemEventArgs evtIn)
        {
            evt = evtIn;
        }
    }

    public class FileSystemResult : CompareResult
    {
        public FileSystemResult(string IdentityIn) : base(IdentityIn)
        {
            ResultType = RESULT_TYPE.FILE;
        }
    }

    public class OpenPortResult : CompareResult
    {
        public OpenPortResult(string IdentityIn) : base(IdentityIn)
        {
            ResultType = RESULT_TYPE.PORT;
        }
    }

    public class RegistryResult : CompareResult
    {
        public RegistryResult(string IdentityIn) : base(IdentityIn)
        {
            ResultType = RESULT_TYPE.REGISTRY;
        }
    }

    public class ServiceResult : CompareResult
    {
        public ServiceResult(string IdentityIn) : base(IdentityIn)
        {
            ResultType = RESULT_TYPE.SERVICE;
        }
    }

    public class UserAccountResult : CompareResult
    {
        public UserAccountResult(string IdentityIn) : base(IdentityIn)
        {
            ResultType = RESULT_TYPE.USER;
        }
    }

    public class CertificateResult : CompareResult
    {
        public CertificateResult(string IdentityIn) : base(IdentityIn)
        {
            ResultType = RESULT_TYPE.CERTIFICATE;
        }
    }
}
