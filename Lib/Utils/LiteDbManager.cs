// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using LiteDB;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class LiteDbManager
    {
        private const int SCHEMA_VERSION = 1;

        private static bool WriterStarted = false;

        private static ConcurrentBag<ILiteCollection<WriteObject>> WriteObjectCollections = new ConcurrentBag<ILiteCollection<WriteObject>>();

        private static Settings settings { get; set; } = new Settings() { SchemaVersion = SCHEMA_VERSION, ShardingFactor = 1, TelemetryEnabled = true };

        public static ConcurrentQueue<WriteObject> WriteQueue { get; private set; } = new ConcurrentQueue<WriteObject>();

        public static bool FirstRun { get; private set; } = true;

        public static LiteDatabase? db { get; private set; }

        public static string Filename { get; private set; } = "asa.litedb";

        public static bool Setup(string filename = "")
        {
            if (!string.IsNullOrEmpty(filename))
            {
                Filename = filename;
            }

            if (db != null)
            {
                CloseDatabase();
            }

            try
            {
                db = new LiteDatabase(Filename);

                db.BeginTrans();

                var col = db.GetCollection<WriteObject>("WriteObjects");

                col.EnsureIndex(x => x.ColObj.Identity);
                col.EnsureIndex(x => x.InstanceHash);
                col.EnsureIndex(x => x.ColObj.ResultType);
                col.EnsureIndex(x => x.RunId);

                var cr = db.GetCollection<CompareResult>("CompareResults");

                cr.EnsureIndex(x => x.BaseRunId);
                cr.EnsureIndex(x => x.CompareRunId);
                cr.EnsureIndex(x => x.ResultType);

                db.Commit();
            }
            catch (Exception e)
            {
                Log.Debug(e, "Initializing database.");
            }

            if (!WriterStarted)
            {
                ((Action)(async () =>
                {
                    await Task.Run(() => KeepSleepAndFlushQueue()).ConfigureAwait(false);
                }))();
                WriterStarted = true;
            }

            return true;
        }

        public static List<DataRunModel> GetResultModels(RUN_STATUS status)
        {
            var output = new List<DataRunModel>();
            var comparisons = db?.GetCollection<Comparison>("Comparisons");

            var results = comparisons?.Find(x => x.Status.Equals(status));

            if (results != null)
            {
                foreach (var result in results)
                {
                    output.Add(new DataRunModel(KeyIn: result.FirstRunId + " vs. " + result.SecondRunId, TextIn: result.FirstRunId + " vs. " + result.SecondRunId));
                }
            }

            return output;
        }

        public static void TrimToLatest()
        {
            List<string> Runs = new List<string>();

            var runs = db?.GetCollection<AsaRun>("Runs");

            var all = runs?.FindAll();

            if (all != null)
            {
                var allButLatest = all.Except(new List<AsaRun>() { all.Last() });

                foreach (var run in allButLatest)
                {
                    DeleteRun(run.RunId);
                }
            }

        }

        public static bool HasElements()
        {
            return !WriteQueue.IsEmpty;
        }

        public static void KeepSleepAndFlushQueue()
        {
            while (true)
            {
                SleepAndFlushQueue();
            }
        }
        public static void SleepAndFlushQueue()
        {
            while (!WriteQueue.IsEmpty)
            {
                WriteNext();
            }
            Thread.Sleep(100);
        }

        public static PLATFORM RunIdToPlatform(string runid)
        {
            var col = db?.GetCollection<AsaRun>("Runs");

            var results = col?.Find(x => x.RunId.Equals(runid));
            if (results.Any())
            {
                return results.First().Platform;
            }
            else
            {
                return PLATFORM.UNKNOWN;
            }
        }

        public static List<WriteObject> GetResultsByRunid(string runid)
        {
            var output = new List<WriteObject>();

            var wo = db?.GetCollection<WriteObject>("WriteObjects");

            return wo?.Find(x => x.RunId.Equals(runid)).ToList() ?? new List<WriteObject>();
        }

        public static void InsertAnalyzed(CompareResult objIn)
        {
            if (objIn != null)
            {
                var cr = db?.GetCollection<CompareResult>("CompareResults");

                cr?.Insert(objIn);
            }
        }

        public static void VerifySchemaVersion()
        {
            //var settings = db.GetCollection<Setting>("Settings");

            //if (!(settings.Exists(Query.And(Query.EQ("Name", "SchemaVersion"), Query.EQ("Value", SCHEMA_VERSION)))))
            //{
            //    Log.Fatal("Schema version of database is {0} but {1} is required. Use config --reset-database to delete the incompatible database.", settings.FindOne(x => x.Name.Equals("SchemaVersion")).Value, SCHEMA_VERSION);
            //    Environment.Exit(-1);
            //}
        }

        public static List<string> GetLatestRunIds(int numberOfIds, RUN_TYPE type)
        {
            var runs = db?.GetCollection<AsaRun>("Runs");
            var selectedRuns = runs?.Find(Query.All(Query.Descending)).Where(x => x.Type == type).Select(x => x.RunId).Take(numberOfIds).ToList() ?? new List<string>();
            return selectedRuns;
        }

        public static Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId)
        {
            var outDict = new Dictionary<RESULT_TYPE, int>() { };

            var wo = db?.GetCollection<WriteObject>("WriteObjects");

            foreach (RESULT_TYPE? resultType in Enum.GetValues(typeof(RESULT_TYPE)))
            {
                if (resultType is RESULT_TYPE _TYPE)
                {
                    var count = wo?.Count(x => x.ColObj.ResultType.Equals(_TYPE)) ?? 0;

                    if (count > 0)
                    {
                        outDict.Add(_TYPE, count);
                    }
                }
            }

            return outDict;
        }

        public static int GetNumResults(RESULT_TYPE ResultType, string runId)
        {
            var wo = db?.GetCollection<WriteObject>("WriteObjects");

            return wo?.Count(Query.And(Query.EQ("RunId", runId), Query.EQ("ColObj.ResultType", (int)ResultType))) ?? 0;
        }

        public static IEnumerable<FileMonitorEvent> GetSerializedMonitorResults(string runId)
        {
            //List<FileMonitorEvent> records = new List<FileMonitorEvent>();

            //var fme = db.GetCollection<FileMonitorEvent>("FileMonitorEvents");

            //return fme.Find(x => x.RunId.Equals(runId));
            return new List<FileMonitorEvent>();
        }

        public static void InsertRun(string runId, List<RESULT_TYPE> typeList, RUN_TYPE type)
        {
            var runs = db?.GetCollection<AsaRun>("Runs");

            runs?.Insert(new AsaRun(
                RunId: runId,
                ResultTypes: typeList,
                Platform: AsaHelpers.GetPlatform(),
                Timestamp: DateTime.Now,
                Type: type,
                Version: AsaHelpers.GetVersionString()
            ));
        }

        public static List<RESULT_TYPE> GetResultTypes(string runId)
        {
            var runs = db?.GetCollection<AsaRun>("Runs");

            var run = runs?.FindOne(x => x.RunId.Equals(runId));

            return run?.ResultTypes ?? new List<RESULT_TYPE>();
        }

        public static void CloseDatabase()
        {
            db?.Rollback();
            db?.Dispose();
            db = null;
        }

        public static void Write(CollectObject objIn, string runId)
        {
            if (objIn != null && runId != null)
            {
                WriteQueue.Enqueue(new WriteObject(objIn, runId));
            }
        }

        public static void InsertCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            var crs = db?.GetCollection<CompareRun>("CompareRun");

            var cr = new CompareRun(FirstRunIdIn: firstRunId, SecondRunIdIn: secondRunId, RunStatusIn: runStatus);

            crs?.Insert(cr);
        }

        public static void WriteNext()
        {
            var list = new List<WriteObject>();

            for (int i = 0; i < Math.Min(1000, WriteQueue.Count); i++)
            {
                WriteObject ColObj;
                WriteQueue.TryDequeue(out ColObj);
                list.Add(ColObj);
            }

            var col = db?.GetCollection<WriteObject>("WriteObjects");
            col?.Insert(list);
        }

        public static bool RunContains(string runId, string IdentityHash)
        {
            if (!WriteObjectCollections.TryTake(out ILiteCollection<WriteObject>? col))
            {
                col = db?.GetCollection<WriteObject>();
            }

            var output = col?.Exists(y => y.RunId == runId && y.Identity == IdentityHash);

            if (col is ILiteCollection<WriteObject>)
                WriteObjectCollections.Add(col);

            return output ?? false;

        }

        public static WriteObject? GetWriteObject(string RunId, string IdentityHash)
        {
            if (!WriteObjectCollections.TryTake(out ILiteCollection<WriteObject>? col))
            {
                col = db?.GetCollection<WriteObject>();
            }

            var output = col?.FindOne(x => x.Identity == IdentityHash && x.RunId == RunId);

            if (col is ILiteCollection<WriteObject>)
                WriteObjectCollections.Add(col);

            return output;
        }

        //public static IEnumerable<WriteObject> GetMissingFromFirst2(string firstRunId, string secondRunId)
        //{
        //    var col = db.GetCollection<WriteObject>("WriteObjects");

        //    var list = new ConcurrentBag<WriteObject>();

        //    var Stopwatch = System.Diagnostics.Stopwatch.StartNew();

        //    var identityHashes = db.Execute($"SELECT IdentityHash FROM WriteObjects WHERE RunId = @0",
        //            new BsonDocument
        //            {
        //                ["0"] = secondRunId
        //            });

        //    Parallel.ForEach(identityHashes.ToEnumerable(), IdentityHash =>
        //    {
        //        if (WriteObjectExists(firstRunId, IdentityHash["IdentityHash"].AsString))
        //        {
        //            list.Add(GetWriteObject(secondRunId, IdentityHash.AsString));
        //        }
        //    });

        //    Stopwatch.Stop();
        //    var t = TimeSpan.FromMilliseconds(Stopwatch.ElapsedMilliseconds);
        //    var answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
        //                            t.Hours,
        //                            t.Minutes,
        //                            t.Seconds,
        //                            t.Milliseconds);
        //    Log.Debug("Completed getting WriteObjects for {0} in {1}", secondRunId, answer);

        //    return list;
        //}

        public static IEnumerable<WriteObject> GetMissingFromFirst(string firstRunId, string secondRunId)
        {
            var col = db?.GetCollection<WriteObject>("WriteObjects");

            var list = new ConcurrentBag<WriteObject>();

            var wos = col?.Find(x => x.RunId == secondRunId);

            wos.AsParallel().ForAll(wo =>
            {
                if (!WriteObjectExists(firstRunId, wo.Identity))
                {
                    list.Add(wo);
                }
            });

            return wos ?? new List<WriteObject>();
        }

        private static bool WriteObjectExists(string RunId, string IdentityHash)
        {
            var col = db?.GetCollection<WriteObject>("WriteObjects");
            var exists = col?.Exists(x => x.Identity == IdentityHash && x.RunId == RunId);

            return exists ?? false;
        }

        public static IEnumerable<WriteObject> GetWriteObjects(string runId)
        {
            var col = db?.GetCollection<WriteObject>("WriteObjects");

            return col?.Find(Query.EQ("RunId", runId)) ?? new List<WriteObject>();
        }


        public static IEnumerable<(WriteObject, WriteObject)> GetModified(string firstRunId, string secondRunId)
        {
            var col = db?.GetCollection<WriteObject>("WriteObjects");

            var list = new ConcurrentBag<(WriteObject, WriteObject)>();

            Parallel.ForEach(GetWriteObjects(firstRunId).ToList(), WO =>
            {
                var secondItem = col?.FindOne(Query.And(Query.EQ("RunId", secondRunId), Query.EQ("IdentityHash", WO.Identity), Query.Not("InstanceHash", WO.InstanceHash)));
                if (secondItem is WriteObject WO2)
                {
                    list.Add((WO, WO2));
                }
            });

            return list;
        }

        public static void UpdateCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            var crs = db?.GetCollection<CompareRun>("CompareRun");

            var cr = crs?.FindOne(x => x.FirstRunId.Equals(firstRunId) && x.SecondRunId.Equals(secondRunId));
            if (cr != null)
            {
                cr.Status = runStatus;
                crs?.Update(cr);
            }
        }

        public static void DeleteRun(string runId)
        {
            var Runs = db?.GetCollection<AsaRun>("Runs");

            Runs?.DeleteMany(x => x.RunId == runId);

            var Results = db?.GetCollection<WriteObject>("WriteObjects");

            Results?.DeleteMany(x => x.RunId == runId);
        }

        public static bool GetOptOut()
        {
            //var settings = db.GetCollection<Setting>("Settings");
            //var optout = settings.FindOne(x => x.Name == "TelemetryOptOut");
            //return bool.Parse(optout.Value);
            return false;
        }

        public static void SetOptOut(bool OptOut)
        {
            //var settings = db.GetCollection<Setting>("Settings");

            //settings.Upsert(new Setting() { Name = "TelemetryOptOut", Value = OptOut.ToString() });
        }

        //public static void WriteFileMonitor(FileMonitorObject obj, string runId)
        //{
        //    var fme = db.GetCollection<FileMonitorEvent>();

        //    fme.Insert(new FileMonitorEvent()
        //    {
        //        RunId = runId,
        //        FMO = obj
        //    });
        //}

        public static AsaRun? GetRun(string RunId)
        {
            var runs = db?.GetCollection<AsaRun>("Runs");

            return runs?.FindOne(Query.EQ("RunId", RunId));
        }

        public static List<string> GetMonitorRuns()
        {
            return GetRuns("monitor");
        }

        public static List<string> GetRuns(string type)
        {
            var runs = db?.GetCollection<AsaRun>("Runs");

            return runs?.Find(x => x.Type.Equals(type)).Select(x => x.RunId)?.ToList() ?? new List<string>();
        }

        public static List<string> GetRuns()
        {
            return GetRuns("collect");
        }

        public static List<FileMonitorEvent> GetMonitorResults(string runId, int offset, int numResults)
        {
            //var fme = db.GetCollection<FileMonitorEvent>("FileMonitorEvents");
            //return fme.Find(x => x.RunId.Equals(runId), skip: offset, limit: numResults).ToList();
            return new List<FileMonitorEvent>();
        }

        public static int GetNumMonitorResults(string runId)
        {
            //var fme = db.GetCollection<FileMonitorEvent>("FileMonitorEvent");
            //return fme.Count(x => x.RunId.Equals(runId));
            return 0;
        }

        public static IEnumerable<CompareResult>? GetComparisonResults(string firstRunId, string secondRunId, RESULT_TYPE resultType, int offset = 0, int numResults = 2147483647)
        {
            var crs = db?.GetCollection<CompareResult>("CompareResult");
            return crs?.Find(x => x.BaseRunId != null && x.CompareRunId != null && x.BaseRunId.Equals(firstRunId) && x.CompareRunId.Equals(secondRunId) && x.ResultType.Equals(resultType), offset, numResults);
        }

        public static int? GetComparisonResultsCount(string firstRunId, string secondRunId, int resultType)
        {
            var crs = db?.GetCollection<CompareResult>("CompareResult");

            return crs?.Count(x => x.BaseRunId != null && x.CompareRunId != null && x.BaseRunId.Equals(firstRunId) && x.CompareRunId.Equals(secondRunId) && x.ResultType.Equals(resultType));
        }

        public static IEnumerable<RESULT_TYPE>? GetCommonResultTypes(string baseId, string compareId)
        {
            var runs = db?.GetCollection<AsaRun>("Runs");

            var firstRun = runs?.FindOne(x => x.RunId.Equals(baseId));
            var secondRun = runs?.FindOne(x => x.RunId.Equals(compareId));

            return firstRun?.ResultTypes.Intersect(secondRun?.ResultTypes);
        }

        public static bool? GetComparisonCompleted(string firstRunId, string secondRunId)
        {
            var cr = db?.GetCollection<CompareRun>("CompareRuns");

            return cr?.Exists(x => x.FirstRunId != null && x.SecondRunId != null && x.FirstRunId.Equals(firstRunId) && x.SecondRunId.Equals(secondRunId));
        }

        public static void BeginTransaction()
        {
            db?.BeginTrans();
        }

        public static void Commit()
        {
            db?.Commit();
        }

        public static void Destroy()
        {
            try
            {
                File.Delete(Filename);
            }
            catch(Exception e)
            {
                Log.Information(e,$"Failed to clean up database located at {Filename}");
            }
        }
    }
    public class Comparison
    {
        public string FirstRunId { get; set; }
        public string SecondRunId { get; set; }
        public RUN_STATUS Status { get; set; }
        public int Id { get; set; }

        public Comparison(string firstRunId, string secondRunId, RUN_STATUS status)
        {
            FirstRunId = firstRunId;
            SecondRunId = secondRunId;
            Status = status;
        }
    }

    public class CompareRun
    {
        public string FirstRunId { get; }
        public string SecondRunId { get; }
        public RUN_STATUS Status { get; set; }

        public CompareRun(string FirstRunIdIn, string SecondRunIdIn, RUN_STATUS RunStatusIn)
        {
            FirstRunId = FirstRunIdIn;
            SecondRunId = SecondRunIdIn;
            Status = RunStatusIn;
        }

    }
}
