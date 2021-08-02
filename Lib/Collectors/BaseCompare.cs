// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using KellermanSoftware.CompareNetObjects;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     The Generic Compare class.
    /// </summary>
    public class BaseCompare
    {
        public BaseCompare()
        {
            Results = new ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), List<CompareResult>>();
            foreach (RESULT_TYPE? result_type in Enum.GetValues(typeof(RESULT_TYPE)))
            {
                foreach (CHANGE_TYPE? change_type in Enum.GetValues(typeof(CHANGE_TYPE)))
                {
                    if (result_type is RESULT_TYPE r && change_type is CHANGE_TYPE c)
                    {
                        Results[(r, c)] = new List<CompareResult>();
                    }
                }
            }
        }

        public ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), List<CompareResult>> Results { get; }

        /// <summary>
        ///     Creates a list of Diff objects based on an object property and findings.
        /// </summary>
        /// <param name="prop"> The property of the referenced object. </param>
        /// <param name="added"> The added findings. </param>
        /// <param name="removed"> The removed findings. </param>
        /// <returns> </returns>
        public static List<Diff> GetDiffs(PropertyInfo prop, object? added, object? removed)
        {
            List<Diff> diffsOut = new List<Diff>();
            if (added != null && prop != null)
            {
                diffsOut.Add(new Diff(FieldIn: prop.Name, AfterIn: added));
            }
            if (removed != null && prop != null)
            {
                diffsOut.Add(new Diff(FieldIn: prop.Name, BeforeIn: removed));
            }
            return diffsOut;
        }

        public void Compare(IEnumerable<CollectObject> FirstRunObjects, IEnumerable<CollectObject> SecondRunObjects, string? firstRunId, string secondRunId)
        {
            if (firstRunId == null)
            {
                throw new ArgumentNullException(nameof(firstRunId));
            }
            if (secondRunId == null)
            {
                throw new ArgumentNullException(nameof(secondRunId));
            }

            var differentObjectsAdded = FirstRunObjects.Where(x => !SecondRunObjects.Any(y => x.Identity == y.Identity && x.ResultType == y.ResultType)).Select(y => (y, firstRunId));
            var differentObjectsRemoved = SecondRunObjects.Where(x => !FirstRunObjects.Any(y => x.Identity == y.Identity && x.ResultType == y.ResultType)).Select(y => (y, secondRunId));
            var differentObjects = differentObjectsAdded.Union(differentObjectsRemoved);

            var modifiedObjects = FirstRunObjects.SelectMany(x => SecondRunObjects.Where(y => x.Identity == y.Identity && x.ResultType == y.ResultType && x.RowKey != y.RowKey).
                                    Select(z => (x, z)));

            Compare(differentObjects, modifiedObjects, firstRunId, secondRunId);
        }

        /// <summary>
        ///     Compares all the common collectors between two runs.
        /// </summary>
        /// <param name="firstRunId"> The Base run id. </param>
        /// <param name="secondRunId"> The Compare run id. </param>
        public void Compare(string? firstRunId, string secondRunId, DatabaseManager databaseManager)
        {
            if (firstRunId == null)
            {
                if (secondRunId == null)
                {
                    throw new ArgumentNullException(nameof(firstRunId));
                }
            }

            if (databaseManager == null)
            {
                throw new ArgumentNullException(nameof(databaseManager));
            }

            IEnumerable<(CollectObject, string)> differentObjects;
            IEnumerable<(CollectObject, CollectObject)> modifyObjects = new List<(CollectObject, CollectObject)>();
            // Single run export mode
            if (firstRunId == null)
            {
                differentObjects = databaseManager.GetResultsByRunid(secondRunId).Select(x => (x.ColObj, x.RunId));
            }
            else
            {
                differentObjects = databaseManager.GetAllMissing(firstRunId, secondRunId).Select(y => (y.ColObj, y.RunId));
                modifyObjects = databaseManager.GetModified(firstRunId, secondRunId).Select(y => (y.Item1.ColObj, y.Item2.ColObj));
            }

            Compare(differentObjects, modifyObjects, firstRunId, secondRunId);
        }

        public void Compare(IEnumerable<(CollectObject, string)> differentObjects, IEnumerable<(CollectObject, CollectObject)> modifiedObjects, string? firstRunId, string secondRunId)
        {
            differentObjects?.AsParallel().ForAll(different =>
            {
                var colObj = different.Item1;
                var obj = new CompareResult()
                {
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                };

                if (different.Item2.Equals(firstRunId))
                {
                    obj.Base = colObj;
                    Results[(colObj.ResultType, CHANGE_TYPE.DELETED)].Add(obj);
                }
                else if (different.Item2.Equals(secondRunId))
                {
                    obj.Compare = colObj;
                    Results[(colObj.ResultType, CHANGE_TYPE.CREATED)].Add(obj);
                }
            });

            modifiedObjects?.AsParallel().ForAll(modified =>
            {
                var compareLogic = new CompareLogic();
                compareLogic.Config.IgnoreCollectionOrder = true;
                var first = modified.Item1;
                var second = modified.Item2;

                if (first != null && second != null)
                {
                    var obj = new CompareResult()
                    {
                        Base = first,
                        Compare = second,
                        BaseRunId = firstRunId,
                        CompareRunId = secondRunId
                    };

                    var properties = first.GetType().GetProperties();

                    if (properties is PropertyInfo[])
                    {
                        foreach (var prop in properties)
                        {
                            try
                            {
                                if (Attribute.IsDefined(prop, typeof(SkipCompareAttribute)))
                                {
                                    continue;
                                }
                                List<Diff> diffs;
                                object? added = null;
                                object? removed = null;

                                object? firstProp = prop.GetValue(first);
                                object? secondProp = prop.GetValue(second);
                                if (firstProp == null && secondProp == null)
                                {
                                    continue;
                                }
                                else if (firstProp == null && secondProp != null)
                                {
                                    added = prop.GetValue(second);
                                    diffs = GetDiffs(prop, added, null);
                                }
                                else if (secondProp == null && firstProp != null)
                                {
                                    removed = prop.GetValue(first);
                                    diffs = GetDiffs(prop, null, removed);
                                }
                                else
                                {
                                    var firstVal = prop.GetValue(first);
                                    var secondVal = prop.GetValue(second);

                                    if (firstVal is List<string> && secondVal is List<string>)
                                    {
                                        added = ((List<string>)secondVal).Except((List<string>)firstVal);
                                        removed = ((List<string>)firstVal).Except((List<string>)secondVal);
                                        if (!((IEnumerable<string>)added).Any())
                                        {
                                            added = null;
                                        }
                                        if (!((IEnumerable<string>)removed).Any())
                                        {
                                            removed = null;
                                        }
                                    }
                                    else if (firstVal is List<KeyValuePair<string, string>> && secondVal is List<KeyValuePair<string, string>>)
                                    {
                                        added = ((List<KeyValuePair<string, string>>)secondVal).Except((List<KeyValuePair<string, string>>)firstVal);
                                        removed = ((List<KeyValuePair<string, string>>)firstVal).Except((List<KeyValuePair<string, string>>)secondVal);
                                        if (!((IEnumerable<KeyValuePair<string, string>>)added).Any())
                                        {
                                            added = null;
                                        }
                                        if (!((IEnumerable<KeyValuePair<string, string>>)removed).Any())
                                        {
                                            removed = null;
                                        }
                                    }
                                    else if (firstVal is Dictionary<string, string> && secondVal is Dictionary<string, string>)
                                    {
                                        added = ((Dictionary<string, string>)secondVal)
                                            .Except((Dictionary<string, string>)firstVal)
                                            .ToDictionary(x => x.Key, x => x.Value);

                                        removed = ((Dictionary<string, string>)firstVal)
                                            .Except((Dictionary<string, string>)secondVal)
                                            .ToDictionary(x => x.Key, x => x.Value);
                                        if (!((IEnumerable<KeyValuePair<string, string>>)added).Any())
                                        {
                                            added = null;
                                        }
                                        if (!((IEnumerable<KeyValuePair<string, string>>)removed).Any())
                                        {
                                            removed = null;
                                        }
                                    }
                                    else if (firstVal is Dictionary<string, List<string>> firstDictionary && secondVal is Dictionary<string, List<string>> secondDictionary)
                                    {
                                        added = secondDictionary
                                            .Except(firstDictionary)
                                            .ToDictionary(x => x.Key, x => x.Value);

                                        removed = firstDictionary
                                            .Except(secondDictionary)
                                            .ToDictionary(x => x.Key, x => x.Value);
                                        if (!((Dictionary<string, List<string>>)added).Any())
                                        {
                                            added = null;
                                        }
                                        if (!((Dictionary<string, List<string>>)removed).Any())
                                        {
                                            removed = null;
                                        }
                                    }
                                    else if (firstVal is Dictionary<(TpmAlgId, uint), byte[]> firstTpmAlgDict && secondVal is Dictionary<(TpmAlgId, uint), byte[]> secondTpmAlgDict)
                                    {
                                        added = secondTpmAlgDict.Where(x => !firstTpmAlgDict.ContainsKey(x.Key) || !firstTpmAlgDict[x.Key].SequenceEqual(x.Value));
                                        removed = firstTpmAlgDict.Where(x => !secondTpmAlgDict.ContainsKey(x.Key) || !secondTpmAlgDict[x.Key].SequenceEqual(x.Value));

                                        if (!((IEnumerable<KeyValuePair<(TpmAlgId, uint), byte[]>>)added).Any())
                                        {
                                            added = null;
                                        }
                                        if (!((IEnumerable<KeyValuePair<(TpmAlgId, uint), byte[]>>)removed).Any())
                                        {
                                            removed = null;
                                        }
                                    }
                                    else if ((firstVal is string || firstVal is int || firstVal is bool) && (secondVal is string || secondVal is int || secondVal is bool))
                                    {
                                        if (!compareLogic.Compare(firstVal, secondVal).AreEqual)
                                        {
                                            obj.Diffs.Add(new Diff(prop.Name, firstVal, secondVal));
                                        }
                                    }
                                    else if (firstProp != null && secondProp != null && compareLogic.Compare(firstVal, secondVal).AreEqual)
                                    {
                                        continue;
                                    }
                                    else
                                    {
                                        obj.Diffs.Add(new Diff(prop.Name, firstVal, secondVal));
                                    }

                                    diffs = GetDiffs(prop, added, removed);
                                }
                                foreach (var diff in diffs)
                                {
                                    obj.Diffs.Add(diff);
                                }
                            }
                            catch (InvalidCastException e)
                            {
                                Log.Debug(e, $"Failed to cast {JsonConvert.SerializeObject(prop)}");
                            }
                            catch (Exception e)
                            {
                                Log.Debug(e, "Generic exception. Tell a programmer.");
                            }
                        }
                    }

                    Results[(first.ResultType, CHANGE_TYPE.MODIFIED)].Add(obj);
                }
            });

            foreach (var empty in Results.Where(x => x.Value.Count == 0))
            {
                Results.Remove(empty.Key, out _);
            }
        }

        /// <summary>
        ///     Returns if the comparators are still running.
        /// </summary>
        /// <returns> RUN_STATUS indicating run status. </returns>
        public RUN_STATUS IsRunning()
        {
            return _running;
        }

        /// <summary>
        ///     Set status to running.
        /// </summary>
        public void Start()
        {
            _running = RUN_STATUS.RUNNING;
        }

        /// <summary>
        ///     Sets status to completed.
        /// </summary>
        public void Stop()
        {
            _running = RUN_STATUS.COMPLETED;
        }

        /// <summary>
        ///     Compare but with Start/Stop automatic
        /// </summary>
        /// <param name="firstRunId"> The Base run id. </param>
        /// <param name="secondRunId"> The Compare run id. </param>
        /// <returns> </returns>
        public bool TryCompare(string? firstRunId, string secondRunId, DatabaseManager databaseManager)
        {
            Start();
            Compare(firstRunId, secondRunId, databaseManager);
            Stop();
            return true;
        }

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;
    }
}