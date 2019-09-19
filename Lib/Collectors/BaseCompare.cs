// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// The Generic Compare class.
    /// </summary>
    public class BaseCompare
    {
        public Dictionary<string, List<CompareResult>> Results { get; protected set; }

        public BaseCompare()
        {
            Results = new Dictionary<string, List<CompareResult>>();
        }

        /// <summary>
        /// Deserialize a Collect object from a RawCollectResult
        /// </summary>
        /// <param name="res">The RawCollectResult containing the JsonSerialized object to hydrate.</param>
        /// <returns>An appropriately typed collect object based on the collect result passed in, or null if the RESULT_TYPE is unknown.</returns>
        public static CollectObject Hydrate(RawCollectResult res)
        {
            switch (res.ResultType)
            {
                case RESULT_TYPE.CERTIFICATE:
                    return JsonConvert.DeserializeObject<CertificateObject>(res.Serialized);
                case RESULT_TYPE.FILE:
                    return JsonConvert.DeserializeObject<FileSystemObject>(res.Serialized);
                case RESULT_TYPE.PORT:
                    return JsonConvert.DeserializeObject<OpenPortObject>(res.Serialized);
                case RESULT_TYPE.REGISTRY:
                    return JsonConvert.DeserializeObject<RegistryObject>(res.Serialized);
                case RESULT_TYPE.SERVICE:
                    return JsonConvert.DeserializeObject<ServiceObject>(res.Serialized);
                case RESULT_TYPE.USER:
                    return JsonConvert.DeserializeObject<UserAccountObject>(res.Serialized);
                case RESULT_TYPE.GROUP:
                    return JsonConvert.DeserializeObject<GroupAccountObject>(res.Serialized);
                case RESULT_TYPE.FIREWALL:
                    return JsonConvert.DeserializeObject<FirewallObject>(res.Serialized);
                case RESULT_TYPE.COM:
                    return JsonConvert.DeserializeObject<ComObject>(res.Serialized);
                default:
                    return null;
            }
        }

        /// <summary>
        /// Compares all the common collectors between two runs.
        /// </summary>
        /// <param name="firstRunId">The Base run id.</param>
        /// <param name="secondRunId">The Compare run id.</param>
        public void Compare(string firstRunId, string secondRunId)
        {
            if (firstRunId == null)
            {
                throw new ArgumentNullException("firstRunId");
            }
            if (secondRunId == null)
            {
                throw new ArgumentNullException("secondRunId");
            }
            List<RawCollectResult> addRows = DatabaseManager.GetMissingFromFirst(firstRunId, secondRunId);
            List<RawCollectResult> removeObjects = DatabaseManager.GetMissingFromFirst(secondRunId, firstRunId);
            List<RawModifiedResult> modifyObjects = DatabaseManager.GetModified(firstRunId, secondRunId);

            Dictionary<string, List<CompareResult>> results = new Dictionary<string, List<CompareResult>>();

            foreach (var added in addRows)
            {
                var obj = new CompareResult()
                {
                    Compare = Hydrate(added),
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    CompareRowKey = added.RowKey,
                    ChangeType = CHANGE_TYPE.CREATED,
                    ResultType = added.ResultType,
                    Identity = added.Identity
                };

                if (results.ContainsKey(String.Format("{0}_{1}", added.ResultType.ToString(), CHANGE_TYPE.CREATED.ToString())))
                {
                    results[String.Format("{0}_{1}", added.ResultType.ToString(), CHANGE_TYPE.CREATED.ToString())].Add(obj);
                }
                else
                {
                    results[String.Format("{0}_{1}", added.ResultType.ToString(), CHANGE_TYPE.CREATED.ToString())] = new List<CompareResult>() { obj };
                }
            }
            foreach (var removed in removeObjects)
            {
                var obj = new CompareResult()
                {
                    Base = Hydrate(removed),
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    BaseRowKey = removed.RowKey,
                    ChangeType = CHANGE_TYPE.DELETED,
                    ResultType = removed.ResultType,
                    Identity = removed.Identity
                };
                if (results.ContainsKey(String.Format("{0}_{1}", removed.ResultType.ToString(), CHANGE_TYPE.DELETED.ToString())))
                {
                    results[String.Format("{0}_{1}", removed.ResultType.ToString(), CHANGE_TYPE.DELETED.ToString())].Add(obj);
                }
                else
                {
                    results[String.Format("{0}_{1}", removed.ResultType.ToString(), CHANGE_TYPE.DELETED.ToString())] = new List<CompareResult>() { obj };
                }
            }
            foreach (var modified in modifyObjects)
            {
                var first = Hydrate(modified.First);
                var second = Hydrate(modified.Second);
                var obj = new CompareResult()
                {
                    Base = first,
                    Compare = second,
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    BaseRowKey = modified.First.RowKey,
                    CompareRowKey = modified.Second.RowKey,
                    ChangeType = CHANGE_TYPE.MODIFIED,
                    ResultType = modified.First.ResultType,
                    Identity = modified.First.Identity
                };

                var fields = first.GetType().GetFields();

                foreach (var field in fields)
                {
                    try
                    {
                        var fieldName = field.Name;
                        List<Diff> diffs;
                        object added = null;
                        object removed = null;
                        object changed = new object();
                        if (field.GetValue(first) == null && field.GetValue(second) == null)
                        {
                            continue;
                        }
                        else if (field.GetValue(first) == null && field.GetValue(second) != null)
                        {
                            added = field.GetValue(second);
                            diffs = GetDiffs(field, added, null);
                        }
                        else if (field.GetValue(second) == null && field.GetValue(first) != null)
                        {
                            removed = field.GetValue(first);
                            diffs = GetDiffs(field, null, removed);
                        }
                        else if (field.GetValue(first).Equals(field.GetValue(second)))
                        {
                            continue;
                        }
                        else
                        {
                            var firstVal = field.GetValue(first);
                            var secondVal = field.GetValue(second);

                            if (Helpers.IsList(firstVal))
                            {
                                try
                                {
                                    added = ((List<object>)field.GetValue(second)).Except((List<object>)field.GetValue(first));
                                    removed = ((List<object>)field.GetValue(first)).Except((List<object>)field.GetValue(second));
                                    if (((IEnumerable<object>)added).Count() == 0)
                                    {
                                        added = null;
                                    }
                                    if (((IEnumerable<object>)removed).Count() == 0)
                                    {
                                        removed = null;
                                    }
                                }
                                catch (Exception e)
                                {
                                    Log.Debug(e, "Error comparing two List<object>s");
                                }
                            }
                            else if (firstVal is List<KeyValuePair<string, string>>)
                            {
                                added = ((List<KeyValuePair<string, string>>)field.GetValue(second)).Except((List<KeyValuePair<string, string>>)field.GetValue(first));
                                removed = ((List<KeyValuePair<string, string>>)field.GetValue(first)).Except((List<KeyValuePair<string, string>>)field.GetValue(second));
                                if (((IEnumerable<KeyValuePair<string, string>>)added).Count() == 0)
                                {
                                    added = null;
                                }
                                if (((IEnumerable<KeyValuePair<string, string>>)removed).Count() == 0)
                                {
                                    removed = null;
                                }
                            }
                            else if (Helpers.IsDictionary(firstVal))
                            {
                                added = ((Dictionary<object, object>)secondVal)
                                    .Except((Dictionary<object, object>)firstVal)
                                    .ToDictionary(x => x.Key, x => x.Value);

                                removed = ((Dictionary<object, object>)firstVal)
                                    .Except((Dictionary<object, object>)secondVal)
                                    .ToDictionary(x => x.Key, x => x.Value);
                                if (((IEnumerable<KeyValuePair<object, object>>)added).Count() == 0)
                                {
                                    added = null;
                                }
                                if (((IEnumerable<KeyValuePair<object, object>>)removed).Count() == 0)
                                {
                                    removed = null;
                                }
                            }
                            else if (firstVal is string || firstVal is int || firstVal is bool || firstVal is ulong)
                            {
                                added = null;
                                removed = null;
                                obj.Diffs.Add(new ModifiedDiff(field.Name, firstVal, secondVal));
                            }
                            else
                            {
                                obj.Diffs.Add(new ModifiedDiff(field.Name, firstVal, secondVal));
                            }

                            diffs = GetDiffs(field, added, removed);
                        }
                        foreach (var diff in diffs)
                        {
                            obj.Diffs.Add(diff);
                        }
                    }
                    catch (InvalidCastException e)
                    {
                        Log.Debug("Failed to cast something to dictionary or string");
                        Logger.DebugException(e);
                    }
                    catch (Exception e)
                    {
                        Logger.DebugException(e);
                    }
                }

                var properties = first.GetType().GetProperties();

                foreach (var prop in properties)
                {
                    try
                    {
                        var propName = prop.Name;
                        List<Diff> diffs;
                        object added = null;
                        object removed = null;
                        object changed = new object();

                        object firstProp = prop.GetValue(first);
                        object secondProp = prop.GetValue(second);
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
                        else if (firstProp != null && secondProp != null && firstProp.Equals(secondProp))
                        {
                            continue;
                        }
                        else
                        {
                            var firstVal = prop.GetValue(first);
                            var secondVal = prop.GetValue(second);

                            if (firstVal is List<string>)
                            {
                                added = ((List<string>)prop.GetValue(second)).Except((List<string>)prop.GetValue(first));
                                removed = ((List<string>)prop.GetValue(first)).Except((List<string>)prop.GetValue(second));
                                if (((IEnumerable<string>)added).Count() == 0)
                                {
                                    added = null;
                                }
                                if (((IEnumerable<string>)removed).Count() == 0)
                                {
                                    removed = null;
                                }
                            }
                            else if (firstVal is List<KeyValuePair<string, string>>)
                            {
                                added = ((List<KeyValuePair<string, string>>)prop.GetValue(second)).Except((List<KeyValuePair<string, string>>)prop.GetValue(first));
                                removed = ((List<KeyValuePair<string, string>>)prop.GetValue(first)).Except((List<KeyValuePair<string, string>>)prop.GetValue(second));
                                if (((IEnumerable<KeyValuePair<string, string>>)added).Count() == 0)
                                {
                                    added = null;
                                }
                                if (((IEnumerable<KeyValuePair<string, string>>)removed).Count() == 0)
                                {
                                    removed = null;
                                }
                            }
                            else if (firstVal is Dictionary<string, string>)
                            {
                                added = ((Dictionary<string, string>)secondVal)
                                    .Except((Dictionary<string, string>)firstVal)
                                    .ToDictionary(x => x.Key, x => x.Value);

                                removed = ((Dictionary<string, string>)firstVal)
                                    .Except((Dictionary<string, string>)secondVal)
                                    .ToDictionary(x => x.Key, x => x.Value);
                                if (((IEnumerable<KeyValuePair<string, string>>)added).Count() == 0)
                                {
                                    added = null;
                                }
                                if (((IEnumerable<KeyValuePair<string, string>>)removed).Count() == 0)
                                {
                                    removed = null;
                                }
                            }
                            else if (firstVal is string || firstVal is int || firstVal is bool)
                            {
                                obj.Diffs.Add(new ModifiedDiff(prop.Name, firstVal, secondVal));
                            }
                            else
                            {
                                obj.Diffs.Add(new ModifiedDiff(prop.Name, firstVal, secondVal));
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
                        Log.Debug("Failed to cast something to dictionary or string");
                        Logger.DebugException(e);
                    }
                    catch (Exception e)
                    {
                        Logger.DebugException(e);
                    }
                }

                if (results.ContainsKey(String.Format("{0}_{1}", modified.First.ResultType.ToString(), CHANGE_TYPE.MODIFIED.ToString())))
                {
                    results[String.Format("{0}_{1}", modified.First.ResultType.ToString(), CHANGE_TYPE.MODIFIED.ToString())].Add(obj);
                }
                else
                {
                    results[String.Format("{0}_{1}", modified.First.ResultType.ToString(), CHANGE_TYPE.MODIFIED.ToString())] = new List<CompareResult>() { obj };
                }
            }
            foreach (string key in results.Keys)
            {
                Results[key] = results[key];
            }
        }

        /// <summary>
        /// Creates a list of Diff objects based on an object field and findings.
        /// </summary>
        /// <param name="field">The field of the referenced object.</param>
        /// <param name="added">The added findings.</param>
        /// <param name="removed">The removed findings.</param>
        /// <returns></returns>
        public List<Diff> GetDiffs(FieldInfo field, object added, object removed)
        {
            List<Diff> diffsOut = new List<Diff>();
            if (added != null)
            {
                diffsOut.Add(new AddDiff()
                {
                    Field = field.Name,
                    Added = added
                });
            }
            if (removed != null)
            {
                diffsOut.Add(new RemoveDiff()
                {
                    Field = field.Name,
                    Removed = removed
                });
            }
            return diffsOut;
        }

        /// <summary>
        /// Creates a list of Diff objects based on an object property and findings.
        /// </summary>
        /// <param name="prop">The property of the referenced object.</param>
        /// <param name="added">The added findings.</param>
        /// <param name="removed">The removed findings.</param>
        /// <returns></returns>
        public List<Diff> GetDiffs(PropertyInfo prop, object added, object removed)
        {
            List<Diff> diffsOut = new List<Diff>();
            if (added != null)
            {
                diffsOut.Add(new AddDiff()
                {
                    Field = prop.Name,
                    Added = added
                });
            }
            if (removed != null)
            {
                diffsOut.Add(new RemoveDiff()
                {
                    Field = prop.Name,
                    Removed = removed
                });
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
            try
            {
                Compare(firstRunId, secondRunId);
                Stop();
                return true;
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Exception from Compare(): {0}", ex.StackTrace);
                Log.Warning(ex.Message);
                Stop();
                return false;
            }
        }

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        protected RESULT_TYPE _type = RESULT_TYPE.UNKNOWN;

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