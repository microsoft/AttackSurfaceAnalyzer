// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Utf8Json;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Analyzer
    {
        private readonly Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DEFAULT_RESULT_TYPE_MAP = new Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>()
        {
            { RESULT_TYPE.CERTIFICATE, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.FILE, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.PORT, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.REGISTRY, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.SERVICE, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.USER, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.UNKNOWN, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.GROUP, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.COM, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.LOG, ANALYSIS_RESULT_TYPE.INFORMATION },
        };
        private readonly PLATFORM OsName;
        private RuleFile config;

        public Analyzer(PLATFORM platform, string? filterLocation = null)
        {
            config = new RuleFile();

            if (string.IsNullOrEmpty(filterLocation))
            {
                LoadEmbeddedFilters();
            }
            else
            {
                LoadFilters(filterLocation);
            }

            OsName = platform;
        }

        public ANALYSIS_RESULT_TYPE Analyze(CompareResult compareResult)
        {
            if (compareResult == null) { return DEFAULT_RESULT_TYPE_MAP[RESULT_TYPE.UNKNOWN]; }
            var results = new List<ANALYSIS_RESULT_TYPE>();
            var curFilters = config.Rules.Where((rule) => (rule.ChangeTypes == null || rule.ChangeTypes.Contains(compareResult.ChangeType))
                                                     && (rule.Platforms == null || rule.Platforms.Contains(OsName))
                                                     && (rule.ResultType.Equals(compareResult.ResultType)))
                                                    .ToList();
            if (curFilters.Count > 0)
            {
                foreach (Rule rule in curFilters)
                {
                    results.Add(Apply(rule, compareResult));
                }

                return results.Max();
            }
            //If there are no filters for a result type
            return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
        }

        public bool VerifyRules()
        {
            var invalid = false;

            foreach (var rule in config.Rules)
            {
                // If clauses have duplicate names
                var duplicateClauses = rule.Clauses.GroupBy(x => x.Label).Where(x => x.Key != null && x.Count() > 1);
                foreach(var duplicateClause in duplicateClauses)
                {
                    invalid = true;
                    Log.Warning($"Rule {rule.Name} has clauses with duplicate name {duplicateClause.Key}.");
                }

                if (rule.Expression is string expression)
                {
                    // Are parenthesis balanced
                    // Are spaces correct
                    // Are all variables defined by clauses?
                    // Are variables and operators alternating?
                    var splits = expression.Split(" ");
                    int foundStarts = 0;
                    int foundEnds = 0;
                    for (int i = 0; i < splits.Length; i++)
                    {
                        foundStarts += splits[i].Count(x => x.Equals('('));
                        foundEnds += splits[i].Count(x => x.Equals(')'));
                        if (foundEnds > foundStarts)
                        {
                            invalid = true;
                            Log.Warning($"Expression {expression} in rule {rule.Name} has unbalanced parentheses.");
                        }
                        // Variable
                        if (i % 2 == 0)
                        {
                            var variable = splits[i].Replace("(", "").Replace(")", "");
                            if (string.IsNullOrWhiteSpace(variable) || !rule.Clauses.Any(x => x.Label == variable))
                            {
                                invalid = true;
                                Log.Warning($"Expression {expression} in rule {rule.Name}  contains undefined label {splits[i].Replace("(", "").Replace(")", "")}");
                            }
                        }
                        //Operator
                        else
                        {
                            if (!Enum.TryParse(typeof(BOOL_OPERATOR), splits[i], out _))
                            {
                                invalid = true;
                                Log.Warning($"Expression {expression} in rule {rule.Name} contains invalid boolean operator {splits[i]}");
                            }
                        }
                    }
                }
            }
            if (invalid)
            {
                Log.Fatal("Invalid Analysis Rules.");
            }
            else
            {
                Log.Information("Analysis Rules Verified Successfully.");
            }
            return !invalid;
        }

        protected ANALYSIS_RESULT_TYPE Apply(Rule rule, CompareResult compareResult)
        {
            if (compareResult != null && rule != null)
            {
                // If we have no clauses we automatically match
                if (!rule.Clauses.Any())
                {
                    compareResult.Rules.Add(rule);
                    return rule.Flag;
                }

                var ClauseResults = new Dictionary<Clause, bool>();
                foreach (Clause clause in rule.Clauses)
                {
                    ClauseResults.Add(clause, AnalyzeClause(clause, compareResult));
                }
               
                if (rule.Expression == null)
                {
                    if (ClauseResults.Where(x => x.Value).Count() == ClauseResults.Count)
                    {
                        compareResult.Rules.Add(rule);
                        return rule.Flag;
                    }
                }
                else
                {
                    if (Evaluate(rule.Expression.Split(" "), ClauseResults))
                    {
                        compareResult.Rules.Add(rule);
                        return rule.Flag;
                    }
                }

                return DEFAULT_RESULT_TYPE_MAP[compareResult.ResultType];
            }
            else
            {
                throw new NullReferenceException();
            }
        }

        private static bool Operate(BOOL_OPERATOR Operator, bool first, bool second)
        {
            switch (Operator)
            {
                case BOOL_OPERATOR.AND:
                    return first && second;
                case BOOL_OPERATOR.OR:
                    return first || second;
                case BOOL_OPERATOR.XOR:
                    return first ^ second;
                case BOOL_OPERATOR.NAND:
                    return !(first && second);
                case BOOL_OPERATOR.NOR:
                    return !(first || second);
                default:
                    return false;
            }
        }

        private static int FindMatchingParen(string[] splits, int startingIndex)
        {
            int foundStarts = 0;
            int foundEnds = 0;
            for (int i = startingIndex; i < splits.Length; i++)
            {
                foundStarts += splits[i].Count(x => x.Equals('('));
                foundEnds += splits[i].Count(x => x.Equals(')'));

                if (foundStarts <= foundEnds)
                {
                    return i;
                }
            }

            return splits.Length - 1;
        }

        private static bool Evaluate(string[] splits, Dictionary<Clause,bool> ClauseResults)
        {
            bool current = false;
            var res = ClauseResults.Where(x => x.Key.Label == splits[0].Replace("(","").Replace(")",""));

            if (!(res.Count() == 1))
            {
                return false;
            }

            current = res.First().Value;

            BOOL_OPERATOR Operator = BOOL_OPERATOR.AND;

            var updated_i = 1;
            for (int i = 1; i < splits.Length; i = updated_i)
            {
                if (i % 2 == 1)
                {
                    Operator = (BOOL_OPERATOR)Enum.Parse(typeof(BOOL_OPERATOR),splits[i]);
                }
                else
                {
                    if (splits[i].StartsWith("("))
                    {
                        //Get the substring closing this paren
                        var matchingParen = FindMatchingParen(splits, i);
                        current = Operate(Operator, current, Evaluate(splits[i..(matchingParen+1)],ClauseResults));
                        updated_i = matchingParen;
                    }
                    else
                    {
                        res = ClauseResults.Where(x => x.Key.Label == splits[i].Replace("(", "").Replace(")", ""));
                        if (!(res.Count() == 1))
                        {
                            return false;
                        }
                        current = Operate(Operator, current, res.First().Value);
                    }
                }
                updated_i = updated_i == i ? i + 1 : updated_i;
            }

            return current;
        }

        private static (List<string>,List<KeyValuePair<string,string>>) ObjectToValues(object? obj)
        {
            var valsToCheck = new List<string>();
            var dictToCheck = new List<KeyValuePair<string, string>>();
            if (obj != null)
            {
                try
                {
                    if (obj is List<string>)
                    {
                        foreach (var value in (List<string>)(obj ?? new List<string>()))
                        {
                            valsToCheck.Add(value);
                        }
                    }
                    else if (obj is Dictionary<string, string>)
                    {
                        dictToCheck = ((Dictionary<string, string>)(obj ?? new Dictionary<string, string>())).ToList();
                    }
                    else if (obj is List<KeyValuePair<string, string>>)
                    {
                        dictToCheck = (List<KeyValuePair<string, string>>)(obj ?? new List<KeyValuePair<string, string>>());
                    }
                    else
                    {
                        var val = obj?.ToString();
                        if (!string.IsNullOrEmpty(val))
                        {
                            valsToCheck.Add(val);
                        }
                    }
                }
                catch (Exception e)
                {
                    Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                    ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                    AsaTelemetry.TrackEvent("ApplyDeletedModifiedException", ExceptionEvent);
                }
            }
            else
            {
                valsToCheck.Add(string.Empty);
            }

            return (valsToCheck, dictToCheck);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Will gather exception information for analysis via telemetry.")]
        protected static bool AnalyzeClause(Clause clause, CompareResult compareResult)
        {
            if (clause == null || compareResult == null)
            {
                return false;
            }
            try
            {
                object? before = null;
                object? after = null;

                if (compareResult.ChangeType == CHANGE_TYPE.CREATED || compareResult.ChangeType == CHANGE_TYPE.MODIFIED)
                {
                    try
                    {
                        var splits = clause.Field.Split('.');
                        after = GetValueByPropertyName(compareResult.Compare, splits[0]);
                        for (int i = 1; i < splits.Length; i++)
                        {
                            after = GetValueByPropertyName(after, splits[i]);
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Information(e, $"Fetching Field {clause.Field} failed from {compareResult.Base?.GetType().ToString() ?? "{null}"}");
                    }
                }
                if (compareResult.ChangeType == CHANGE_TYPE.DELETED || compareResult.ChangeType == CHANGE_TYPE.MODIFIED)
                {
                    try
                    {
                        var splits = clause.Field.Split('.');
                        before = GetValueByPropertyName(compareResult.Base, splits[0]);
                        for (int i = 1; i < splits.Length; i++)
                        {
                            before = GetValueByPropertyName(before, splits[i]);
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Information(e, $"Fetching Field {clause.Field} failed from {compareResult.Base?.GetType().ToString() ?? "{null}"}");
                    }
                }

                (var beforeList, var beforeDict) = ObjectToValues(before);
                (var afterList, var afterDict) = ObjectToValues(after);

                var valsToCheck = beforeList.Union(afterList);
                var dictToCheck = beforeDict.Union(afterDict);

                switch (clause.Operation)
                {
                    case OPERATION.EQ:
                        if (clause.Data is List<string> EqualsData)
                        {   
                            if (EqualsData.Intersect(valsToCheck).Any())
                            {
                                return true;
                            }
                        }
                        return false;

                    case OPERATION.NEQ:
                        if (clause.Data is List<string> NotEqualsData)
                        {
                            if (!NotEqualsData.Intersect(valsToCheck).Any())
                            {
                                return true;
                            }
                        }
                        return false;


                    // If *every* entry of the clause data is matched
                    case OPERATION.CONTAINS:
                        if (dictToCheck.Any())
                        {
                            if (clause.DictData is List<KeyValuePair<string, string>> ContainsData)
                            {
                                if (ContainsData.Where(y => dictToCheck.Where((x) => x.Key == y.Key && x.Value == y.Value).Any()).Count() == ContainsData.Count)
                                {
                                    return true;
                                }
                            }
                        }
                        else if (valsToCheck.Any())
                        {
                            if (clause.Data is List<string> ContainsDataList)
                            {
                                if (ContainsDataList.Intersect(valsToCheck).Count() == ContainsDataList.Count)
                                {
                                    return true;
                                }
                            }
                        }
                        return false;

                    // If *any* entry of the clause data is matched
                    case OPERATION.CONTAINS_ANY:
                        if (dictToCheck.Any())
                        {
                            if (clause.DictData is List<KeyValuePair<string, string>> ContainsData)
                            {
                                foreach (KeyValuePair<string, string> value in ContainsData)
                                {
                                    if (dictToCheck.Where((x) => x.Key == value.Key && x.Value == value.Value).Any())
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                        else if (valsToCheck.Any())
                        {
                            if (clause.Data is List<string> ContainsDataList)
                            {
                                if (clause.Data.Intersect(valsToCheck).Any())
                                {
                                    return true;
                                }
                            }
                        }
                        return false;

                    // If any of the clauses are not contained
                    case OPERATION.DOES_NOT_CONTAIN:
                        if (dictToCheck.Any())
                        {
                            if (clause.DictData is List<KeyValuePair<string, string>> ContainsData)
                            {
                                if (ContainsData.Where(y => dictToCheck.Where((x) => x.Key == y.Key && x.Value == y.Value).Any()).Any())
                                {
                                    return true;
                                }
                                return false;
                            }
                        }
                        else if (valsToCheck.Any())
                        {
                            if (clause.Data is List<string> ContainsDataList)
                            {
                                if (ContainsDataList.Intersect(valsToCheck).Any())
                                {
                                    return true;
                                }
                                return false;
                            }
                        }
                        break;

                case OPERATION.DOES_NOT_CONTAIN_ALL:
                    if (dictToCheck.Any())
                    {
                        if (clause.DictData is List<KeyValuePair<string, string>> ContainsData)
                        {
                            if (ContainsData.Where(y => dictToCheck.Where((x) => x.Key == y.Key && x.Value == y.Value).Any()).Count() == ContainsData.Count)
                            {
                                return true;
                            }
                            return false;
                        }
                    }
                    else if (valsToCheck.Any())
                    {
                        if (clause.Data is List<string> ContainsDataList)
                        {
                            if (ContainsDataList.Intersect(valsToCheck).Count() == ContainsDataList.Count)
                            {
                                return true;
                            }
                            return false;
                        }
                    }
                    break;

                    // If any of the data values are greater than the first provided data value
                    case OPERATION.GT:
                        if (valsToCheck.Where(val => (int.Parse(val, CultureInfo.InvariantCulture) > int.Parse(clause.Data?[0] ?? $"{int.MinValue}", CultureInfo.InvariantCulture))).Any()) { return true; }
                        return false;

                    // If any of the data values are less than the first provided data value
                    case OPERATION.LT:
                        if (valsToCheck.Where(val => (int.Parse(val, CultureInfo.InvariantCulture) < int.Parse(clause.Data?[0] ?? $"{int.MaxValue}", CultureInfo.InvariantCulture))).Any()) { return true; }
                        return false;

                    // If any of the regexes match any of the values
                    case OPERATION.REGEX:
                        if (clause.Data is List<string> RegexList)
                        {
                            var regexList = RegexList.Select(x => new Regex(x));

                            if (valsToCheck.Where(x => regexList.Where(y => y.IsMatch(x)).Any()).Any())
                            {
                                return true;
                            }
                        }
                        return false;

                    // Ignores provided data. Checks if the named property has changed.
                    case OPERATION.WAS_MODIFIED:
                        if (compareResult.ChangeType == CHANGE_TYPE.MODIFIED)
                        {
                            if (beforeList == null || afterList == null)
                            {
                                if (beforeList == null && afterList == null)
                                {
                                    return false;
                                }
                                return true;
                            }

                            if (beforeList.Count == afterList.Count && beforeList.Intersect(afterList).Count() == beforeList.Count)
                            {
                                return false;
                            }
                        }
                        return true;

                    // Ends with any of the provided data
                    case OPERATION.ENDS_WITH:
                        if (clause.Data is List<string> EndsWithData)
                        {
                            if (valsToCheck.Where(x => EndsWithData.Where(y => x.EndsWith(y, StringComparison.CurrentCulture)).Any()).Any())
                            {
                                return true;
                            }
                        }
                        return false;

                    // Starts with any of the provided data
                    case OPERATION.STARTS_WITH:
                        if (clause.Data is List<string> StartsWithData)
                        {
                            if (valsToCheck.Where(x => StartsWithData.Where(y => x.StartsWith(y, StringComparison.CurrentCulture)).Any()).Any())
                            {
                                return true;
                            }
                        }
                        return false;

                    default:
                        Log.Debug("Unimplemented operation {0}", clause.Operation);
                        return false;
                }
            }
            catch (Exception e)
            {
                Log.Debug(e, $"Hit while parsing {JsonSerializer.Serialize(clause)} onto {JsonSerializer.Serialize(compareResult)}");
                Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                AsaTelemetry.TrackEvent("ApplyOverallException", ExceptionEvent);
            }

            return false;
        }

        private static object? GetValueByPropertyName(object? obj, string? propertyName) => obj?.GetType().GetProperty(propertyName ?? string.Empty)?.GetValue(obj);


        public void DumpFilters()
        {
            Log.Verbose("Filter dump:");
            Log.Verbose(JsonSerializer.ToJsonString(config));
        }

        public void LoadEmbeddedFilters()
        {
            try
            {
                var assembly = typeof(FileSystemObject).Assembly;
                var resourceName = "AttackSurfaceAnalyzer.analyses.json";
                using (Stream stream = assembly.GetManifestResourceStream(resourceName) ?? new MemoryStream())
                using (StreamReader reader = new StreamReader(stream))
                {
                    config = JsonSerializer.Deserialize<RuleFile>(reader.ReadToEnd());
                    Log.Information(Strings.Get("LoadedAnalyses"), "Embedded");
                }
                if (config == null)
                {
                    Log.Debug("No filters today.");
                    return;
                }
                DumpFilters();
            }
            catch (Exception e) when (
                e is ArgumentNullException
                || e is ArgumentException
                || e is FileLoadException
                || e is FileNotFoundException
                || e is BadImageFormatException
                || e is NotImplementedException)
            {

                config = new RuleFile();
                Log.Debug("Could not load filters {0} {1}", "Embedded", e.GetType().ToString());

                // This is interesting. We shouldn't hit exceptions when loading the embedded resource.
                Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                AsaTelemetry.TrackEvent("EmbeddedAnalysesFilterLoadException", ExceptionEvent);
            }
        }

        public void LoadFilters(string filterLoc = "")
        {
            if (!string.IsNullOrEmpty(filterLoc))
            {
                try
                {
                    using (StreamReader file = System.IO.File.OpenText(filterLoc))
                    {
                        config = JsonSerializer.Deserialize<RuleFile>(file.ReadToEnd());
                        Log.Information(Strings.Get("LoadedAnalyses"), filterLoc);
                    }
                    if (config == null)
                    {
                        Log.Debug("No filters this time.");
                        return;
                    }
                    DumpFilters();
                }
                catch (Exception e) when (
                    e is UnauthorizedAccessException
                    || e is ArgumentException
                    || e is ArgumentNullException
                    || e is PathTooLongException
                    || e is DirectoryNotFoundException
                    || e is FileNotFoundException
                    || e is NotSupportedException)
                {
                    config = new RuleFile();
                    //Let the user know we couldn't load their file
                    Log.Warning(Strings.Get("Err_MalformedFilterFile"), filterLoc);

                    return;
                }
            }
            
        }
    }
}


