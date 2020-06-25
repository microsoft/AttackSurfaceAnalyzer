﻿// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;

namespace AttackSurfaceAnalyzer.Utils
{
    public abstract class DatabaseManager
    {
        public bool FirstRun { get; internal set; } = true;

        public abstract void BeginTransaction();

        public abstract void CloseDatabase();

        public abstract void Commit();

        public abstract void DeleteRun(string runid);

        public abstract void Destroy();

        public abstract IEnumerable<WriteObject> GetAllMissing(string firstRunId, string secondRunId);

        public List<RESULT_TYPE> GetCommonResultTypes(string baseId, string compareId)
        {
            var runOne = GetRun(baseId);
            var runTwo = GetRun(compareId);

            return runOne?.ResultTypes.Intersect(runTwo?.ResultTypes).ToList() ?? new List<RESULT_TYPE>();
        }

        public abstract bool GetComparisonCompleted(string? firstRunId, string secondRunId);

        public abstract List<CompareResult> GetComparisonResults(string baseId, string compareId, RESULT_TYPE exportType);

        public abstract List<CompareResult> GetComparisonResults(string baseId, string compareId, int resultType, int offset, int numResults);

        public abstract int GetComparisonResultsCount(string baseId, string compareId, int resultType);

        public abstract List<string> GetLatestRunIds(int numberOfIds, RUN_TYPE type);

        public abstract IEnumerable<WriteObject> GetMissingFromFirst(string firstRunId, string secondRunId);

        public abstract IEnumerable<(WriteObject, WriteObject)> GetModified(string firstRunId, string secondRunId);

        public abstract List<FileMonitorObject> GetMonitorResults(string runId, int offset, int numResults);

        public List<string> GetMonitorRuns()
        {
            return GetRuns(RUN_TYPE.MONITOR);
        }

        public abstract int GetNumMonitorResults(string runId);

        public abstract int GetNumResults(RESULT_TYPE ResultType, string runId);

        public abstract List<DataRunModel> GetResultModels(RUN_STATUS runStatus);

        public abstract IEnumerable<WriteObject> GetResultsByRunid(string runid);

        public abstract Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId);

        public abstract AsaRun? GetRun(string RunId);

        public abstract List<string> GetRuns(RUN_TYPE type);

        public List<string> GetRuns()
        {
            return GetRuns(RUN_TYPE.COLLECT);
        }

        public abstract List<FileMonitorEvent> GetSerializedMonitorResults(string runId);

        public abstract Settings? GetSettings();

        public bool GetTelemetryEnabled()
        {
            var settings = GetSettings();
            if (settings != null)
            {
                return settings.TelemetryEnabled;
            }
            return true;
        }

        public abstract void InsertAnalyzed(CompareResult objIn);

        public abstract void InsertCompareRun(string? firstRunId, string secondRunId, RUN_STATUS runStatus);

        public abstract void InsertRun(AsaRun run);

        public static int ModuloString(string identity, int shardingFactor) => identity.Sum(x => x) % shardingFactor;

        public abstract void RollBack();

        public abstract PLATFORM RunIdToPlatform(string runid);

        public abstract void SetSettings(Settings settings);

        public void SetTelemetryEnabled(bool Enabled)
        {
            var settings = GetSettings();
            if (settings != null)
            {
                settings.TelemetryEnabled = Enabled;
                SetSettings(settings);
            }
        }

        public abstract ASA_ERROR Setup();

        public abstract void TrimToLatest();

        public abstract void UpdateCompareRun(string? firstRunId, string secondRunId, RUN_STATUS runStatus);
        public abstract bool HasElements { get; }

        /// <summary>
        ///     Used for testing.
        /// </summary>
        public void WaitUntilFlushed()
        {
            while (HasElements)
            {
                Thread.Sleep(1);
            }
        }

        public abstract void Write(CollectObject? colObj, string? runId);

        public abstract void WriteFileMonitor(FileMonitorObject fmo, string RunId);
    }
}