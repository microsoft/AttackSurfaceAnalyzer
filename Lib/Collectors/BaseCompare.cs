// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using KellermanSoftware.CompareNetObjects;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Utf8Json;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// The Generic Compare class.
    /// </summary>
    public class BaseCompare
    {
        public ConcurrentDictionary<string, ConcurrentQueue<CompareResult>> Results { get; }

        public BaseCompare()
        {
            Results = new ConcurrentDictionary<string, ConcurrentQueue<CompareResult>>();
            foreach (RESULT_TYPE? result_type in Enum.GetValues(typeof(RESULT_TYPE)))
            {
                foreach (CHANGE_TYPE? change_type in Enum.GetValues(typeof(CHANGE_TYPE)))
                {
                    Results[$"{result_type.ToString()}_{change_type.ToString()}"] = new ConcurrentQueue<CompareResult>();
                }
            }
        }

        /// <summary>
        /// Compares all the common collectors between two runs.
        /// </summary>
        /// <param name="firstRunId">The Base run id.</param>
        /// <param name="secondRunId">The Compare run id.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Collecting telemetry on exceptions.")]
        public void Compare(string firstRunId, string secondRunId)
        {
            if (firstRunId == null)
            {
                throw new ArgumentNullException(nameof(firstRunId));
            }
            if (secondRunId == null)
            {
                throw new ArgumentNullException(nameof(secondRunId));
            }

            ConcurrentBag<WriteObject> differentObjects = DatabaseManager.GetAllMissing(firstRunId, secondRunId);
            ConcurrentBag<(WriteObject, WriteObject)> modifyObjects = DatabaseManager.GetModified(firstRunId, secondRunId);

            differentObjects.AsParallel().ForAll(different =>
            {
                if (different.RunId.Equals(firstRunId))
                {
                    var obj = new CompareResult()
                    {
                        Base = different.ColObj,
                        BaseRunId = firstRunId,
                        CompareRunId = secondRunId,
                        BaseRowKey = different.InstanceHash,
                    };

                    Results[$"{different.ColObj?.ResultType}_{CHANGE_TYPE.DELETED}"].Enqueue(obj);
                }
                else if (different.RunId.Equals(secondRunId))
                {
                    var obj = new CompareResult()
                    {
                        Compare = different.ColObj,
                        BaseRunId = firstRunId,
                        CompareRunId = secondRunId,
                        CompareRowKey = different.InstanceHash,
                    };
                    Results[$"{different.ColObj?.ResultType}_{CHANGE_TYPE.CREATED}"].Enqueue(obj);
                }
            });

            modifyObjects.AsParallel().ForAll(modified =>
            {
                var compareLogic = new CompareLogic();
                compareLogic.Config.IgnoreCollectionOrder = true;
                var first = modified.Item1.ColObj;
                var second = modified.Item2.ColObj;
                var obj = new CompareResult()
                {
                    Base = first,
                    Compare = second,
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    BaseRowKey = modified.Item1.InstanceHash,
                    CompareRowKey = modified.Item2.InstanceHash,
                };

                var properties = first?.GetType().GetProperties();

                if (properties is PropertyInfo[])
                {
                    foreach (var prop in properties)
                    {
                        try
                        {
                            var propName = prop.Name;
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
                            else if (firstProp != null && secondProp != null && compareLogic.Compare(firstProp, secondProp).AreEqual)
                            {
                                continue;
                            }
                            else
                            {
                                var firstVal = prop.GetValue(first);
                                var secondVal = prop.GetValue(second);

                                if (firstVal is List<string> && secondVal is List<string>)
                                {
                                    added = ((List<string>)secondVal).Except((List<string>)firstVal);
                                    removed = ((List<string>)firstVal).Except((List<string>?)prop.GetValue(second));
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
                                else if ((firstVal is string || firstVal is int || firstVal is bool) && (secondVal is string || secondVal is int || secondVal is bool))
                                {
                                    obj.Diffs.Add(new Diff(prop.Name, firstVal, secondVal));
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
                            Log.Debug(e, $"Failed to cast {JsonSerializer.Serialize(prop)}");
                        }
                        catch (Exception e)
                        {
                            Log.Debug(e, "Generic exception. Tell a programmer.");
                            Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                            ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                            AsaTelemetry.TrackEvent("CompareException", ExceptionEvent);
                        }
                    }
                }

                Results[$"{modified.Item1.ColObj?.ResultType.ToString()}_{CHANGE_TYPE.MODIFIED}"].Enqueue(obj);
            });

            foreach (var empty in Results.Where(x => x.Value.Count == 0))
            {
                Results.Remove(empty.Key, out _);
            }
        }

        /// <summary>
        /// Creates a list of Diff objects based on an object property and findings.
        /// </summary>
        /// <param name="prop">The property of the referenced object.</param>
        /// <param name="added">The added findings.</param>
        /// <param name="removed">The removed findings.</param>
        /// <returns></returns>
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

        /// <summary>
        /// Compare but with a Try/Catch block for exceptions.
        /// </summary>
        /// <param name="firstRunId">The Base run id.</param>
        /// <param name="secondRunId">The Compare run id.</param>
        /// <returns></returns>
        public bool TryCompare(string firstRunId, string secondRunId)
        {
            Start();
            Compare(firstRunId, secondRunId);
            Stop();
            return true;
        }

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        /// <summary>
        /// Returns if the comparators are still running.
        /// </summary>
        /// <returns>RUN_STATUS indicating run status.</returns>
        public RUN_STATUS IsRunning()
        {
            return _running;
        }

        /// <summary>
        /// Set status to running.
        /// </summary>
        public void Start()
        {
            _running = RUN_STATUS.RUNNING;

        }

        /// <summary>
        /// Sets status to completed.
        /// </summary>
        public void Stop()
        {
            _running = RUN_STATUS.COMPLETED;
        }

    }
}