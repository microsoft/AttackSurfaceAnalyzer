// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AttackSurfaceAnalyzer.Objects
{

    public class RawCollectResult
    {
        public RESULT_TYPE ResultType { get; set; }
        public byte[] RowKey { get; set; }
        public string RunId { get; set; }
        public string Identity { get; set; }
        public byte[] Serialized { get; set; }
    }

    public class RawModifiedResult
    {
        public RawCollectResult First { get; set; }
        public RawCollectResult Second { get; set; }
    }

    public class FileMonitorEvent
    {
        public CHANGE_TYPE ChangeType { get; set; }
        public string Path { get; set; }
        public string OldPath { get; set; }
        public string Name { get; set; }
        public string OldName { get; set; }
    }

    public class CompareResult
    {
        public string Identity { get; set; }
        public CHANGE_TYPE ChangeType { get; set; }
        public RESULT_TYPE ResultType { get; set; }
        public ANALYSIS_RESULT_TYPE Analysis { get; set; }
        public List<Rule> Rules { get; set; }
        public List<Diff> Diffs { get; set; }
        public byte[] BaseRowKey { get; set; }
        public byte[] CompareRowKey { get; set; }
        public string BaseRunId { get; set; }
        public string CompareRunId { get; set; }
        public object Base { get; set; }
        public object Compare { get; set; }

        public bool ShouldSerializeDiffs()
        {
            return (Diffs.Count > 0);
        }

        public bool ShouldSerializeRules()
        {
            return (Rules.Count > 0);
        }

        public CompareResult()
        {
            Rules = new List<Rule>();
            Diffs = new List<Diff>();
        }
    }

    public class OutputFileMonitorResult
    {
        public string RowKey { get; set; }
        public string Timestamp { get; set; }
        public string OldPath { get; set; }
        public string Path { get; set; }
        public string OldName { get; set; }
        public string Name { get; set; }
        public CHANGE_TYPE ChangeType { get; set; }
    }

    public class OutputCompareResult : CompareResult
    {
        public string SerializedBase { get; set; }
        public string SerializedCompare { get; set; }
    }

    public class FileSystemMonitorResult
    {
        public FileSystemEventArgs evt { get; set; }
        public NotifyFilters filter { get; set; }
    }

    public class FileSystemResult : CompareResult
    {
        public FileSystemResult()
        {
            ResultType = RESULT_TYPE.FILE;
        }
    }

    public class OpenPortResult : CompareResult
    {
        public OpenPortResult()
        {
            ResultType = RESULT_TYPE.PORT;
        }
    }

    public class RegistryResult : CompareResult
    {
        public RegistryResult()
        {
            ResultType = RESULT_TYPE.REGISTRY;
        }
    }

    public class ServiceResult : CompareResult
    {
        public ServiceResult()
        {
            ResultType = RESULT_TYPE.SERVICE;
        }
    }

    public class UserAccountResult : CompareResult
    {
        public UserAccountResult()
        {
            ResultType = RESULT_TYPE.USER;
        }
    }

    public class CertificateResult : CompareResult
    {
        public CertificateResult()
        {
            ResultType = RESULT_TYPE.CERTIFICATE;
        }
    }
}
