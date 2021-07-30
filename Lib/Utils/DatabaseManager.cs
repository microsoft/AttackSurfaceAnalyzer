// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public abstract class DatabaseManager
    {
        public bool FirstRun { get; internal set; } = true;
        public abstract bool HasElements { get; }

        public string Location { get; internal set; } = "asa.db";
        public abstract int QueueSize { get; }

        public static void Destroy(string sqliteFilename)
        {
            var directory = Path.GetDirectoryName(sqliteFilename);
            if (string.IsNullOrEmpty(directory))
            {
                directory = ".";
            }
            var toDelete = Directory.EnumerateFiles(directory, sqliteFilename);
            foreach (var file in toDelete)
            {
                File.Delete(file);
            }
        }

        public static int ModuloString(string identity, int shardingFactor) => identity.Sum(x => x) % shardingFactor;

        public abstract void BeginTransaction();

        public abstract void CloseDatabase();

        public abstract void Commit();

        public abstract void DeleteRun(string runid);
        public abstract void DeleteCompareRun(string firstRunid, string secondRunid, string analysisHash);

        public abstract void Destroy();

        public abstract IEnumerable<WriteObject> GetAllMissing(string firstRunId, string secondRunId);

        public List<RESULT_TYPE> GetCommonResultTypes(string baseId, string compareId)
        {
            var runOne = GetRun(baseId);
            var runTwo = GetRun(compareId);

            return runOne?.ResultTypes.Intersect(runTwo?.ResultTypes ?? new List<RESULT_TYPE>()).ToList() ?? (runTwo?.ResultTypes ?? new List<RESULT_TYPE>());
        }

        public abstract bool GetComparisonCompleted(string? firstRunId, string secondRunId, string analysesHash);

        public abstract List<CompareResult> GetComparisonResults(string baseId, string compareId, string analysesHash, RESULT_TYPE exportType);

        public abstract List<CompareResult> GetComparisonResults(string baseId, string compareId, string analysesHash, RESULT_TYPE resultType, int offset, int numResults);

        public abstract int GetComparisonResultsCount(string baseId, string compareId, string analysesHash, int resultType);

        public abstract DBSettings GetCurrentSettings();

        public abstract List<string> GetLatestRunIds(int numberOfIds, RUN_TYPE type);

        public abstract IEnumerable<WriteObject> GetMissingFromFirst(string firstRunId, string secondRunId);

        public abstract IEnumerable<(WriteObject, WriteObject)> GetModified(string firstRunId, string secondRunId);

        public abstract IEnumerable<FileMonitorObject> GetMonitorResults(string runId, int offset = 0, int numResults = -1);

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

        public abstract List<string> GetRuns();

        public abstract List<FileMonitorEvent> GetSerializedMonitorResults(string runId);

        public abstract Settings? GetSettings();

        public abstract void InsertAnalyzed(CompareResult objIn);

        public abstract void InsertCompareRun(string? firstRunId, string secondRunId, string analysesHash, RUN_STATUS runStatus);

        public abstract List<(string firstRunId, string secondRunId, string analysesHash, RUN_STATUS runStatus)> GetCompareRuns();

        public abstract void InsertRun(AsaRun run);

        public abstract void RollBack();

        public abstract PLATFORM RunIdToPlatform(string runid);

        public abstract void SetSettings(Settings settings);

        public abstract ASA_ERROR Setup();

        public abstract void TrimToLatest();

        public abstract void UpdateCompareRun(string? firstRunId, string secondRunId, RUN_STATUS runStatus);

        public abstract void Vacuum();

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
    }
}