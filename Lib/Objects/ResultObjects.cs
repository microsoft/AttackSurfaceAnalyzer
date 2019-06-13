// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using System.Collections.Generic;
using System.IO;

namespace AttackSurfaceAnalyzer.ObjectTypes
{

    public class FileMonitorEvent
    {
        public CHANGE_TYPE ChangeType;
        public string Path;
        public string OldPath;
        public string Name;
        public string OldName;
    }

    public class CompareResult
    {
        public string BaseRowKey;
        public string CompareRowKey;
        public string BaseRunId;
        public string CompareRunId;
        public CHANGE_TYPE ChangeType;
        public RESULT_TYPE ResultType;
        public object Base;
        public object Compare;
        public ANALYSIS_RESULT_TYPE Analysis;
        public List<Rule> Rules;
    }

    public class OutputFileMonitorResult
    {
        public string RowKey;
        public string Timestamp;
        public string OldPath;
        public string Path;
        public string OldName;
        public string Name;
        public CHANGE_TYPE ChangeType;
    }

    public class OutputCompareResult : CompareResult
    {
        public string SerializedBase;
        public string SerializedCompare;
    }

    public class FileSystemResult : CompareResult
    {
        new public FileSystemObject Base;
        new public FileSystemObject Compare;
        public FileSystemResult()
        {
            ResultType = RESULT_TYPE.FILE;
        }
    }

    public class FileSystemMonitorResult
    {
        public FileSystemEventArgs evt;
        public NotifyFilters filter;
    }

    public class OpenPortResult: CompareResult
    {
        new public OpenPortObject Base;
        new public OpenPortObject Compare;
        public OpenPortResult()
        {
            ResultType = RESULT_TYPE.PORT;
        }
    }

    public class RegistryResult: CompareResult
    {
        new public RegistryObject Base;
        new public RegistryObject Compare;
        public RegistryResult()
        {
            ResultType = RESULT_TYPE.REGISTRY;
        }
    }

    public class ServiceResult : CompareResult
    {
        new public ServiceObject Base;
        new public ServiceObject Compare;
        public ServiceResult()
        {
            ResultType = RESULT_TYPE.SERVICES;
        }
    }

    public class UserAccountResult : CompareResult
    {
        new public UserAccountObject Base;
        new public UserAccountObject Compare;
        public UserAccountResult()
        {
            ResultType = RESULT_TYPE.USER;
        }
    }

    public class CertificateResult: CompareResult
    {
        new public CertificateObject Base;
        new public CertificateObject Compare;
        public CertificateResult()
        {
            ResultType = RESULT_TYPE.CERTIFICATE;
        }
    }
}
