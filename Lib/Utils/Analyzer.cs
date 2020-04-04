// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using Microsoft.CodeAnalysis;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Utf8Json;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Analyzer
    {
        private readonly PLATFORM OsName;
        private RuleFile config;

        public Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DefaultLevels { get { return config.DefaultLevels; } }

        private static readonly Dictionary<string, Regex> RegexCache = new Dictionary<string, Regex>();

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

        public Analyzer(PLATFORM platform, RuleFile filters)
        {
            OsName = platform;
            config = filters;
        }

        public ANALYSIS_RESULT_TYPE Analyze(CompareResult compareResult)
        {
            if (compareResult == null) { return config.DefaultLevels[RESULT_TYPE.UNKNOWN]; }
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
            return config.DefaultLevels[compareResult.ResultType];
        }

        public bool VerifyRules()
        {
            var invalid = false;

            foreach (var rule in config.Rules)
            {
                var clauseLabels = rule.Clauses.GroupBy(x => x.Label);

                // If clauses have duplicate names
                var duplicateClauses = clauseLabels.Where(x => x.Key != null && x.Count() > 1);
                foreach (var duplicateClause in duplicateClauses)
                {
                    invalid = true;
                    Log.Warning(Strings.Get("Err_ClauseDuplicateName"), rule.Name, duplicateClause.Key);
                }

                // If clause label contains illegal characters
                foreach (var clause in rule.Clauses)
                {
                    if (clause.Label is string label)
                    {
                        if (label.Contains(" ") || label.Contains("(") || label.Contains(")"))
                        {
                            invalid = true;
                            Log.Warning(Strings.Get("Err_ClauseInvalidLabel"), rule.Name, label);
                        }
                    }
                }

                var foundLabels = new List<string>();

                if (rule.Expression is string expression)
                {
                    // Are parenthesis balanced
                    // Are spaces correct
                    // Are all variables defined by clauses?
                    // Are variables and operators alternating?
                    var splits = expression.Split(" ");
                    int foundStarts = 0;
                    int foundEnds = 0;
                    bool expectingOperator = false;
                    bool previouslyNot = false;
                    for (int i = 0; i < splits.Length; i++)
                    {
                        foundStarts += splits[i].Count(x => x.Equals('('));
                        foundEnds += splits[i].Count(x => x.Equals(')'));
                        if (foundEnds > foundStarts)
                        {
                            invalid = true;
                            Log.Warning(Strings.Get("Err_ClauseUnbalancedParentheses"), expression, rule.Name);
                        }
                        // Variable
                        if (!expectingOperator)
                        {
                            var lastOpen = -1;
                            var lastClose = -1;

                            for (int j = 0; j < splits[i].Length; j++)
                            {
                                // Check that the parenthesis are balanced
                                if (splits[i][j] == '(')
                                {
                                    // If we've seen a ) this is now invalid
                                    if (lastClose != -1)
                                    {
                                        invalid = true;
                                        Log.Warning(Strings.Get("Err_ClauseParenthesisInLabel"), expression, rule.Name, splits[i]);
                                    }
                                    // If there were any characters between open parenthesis
                                    if (j - lastOpen != 1)
                                    {
                                        invalid = true;
                                        Log.Warning(Strings.Get("Err_ClauseCharactersBetweenOpenParentheses"), expression, rule.Name, splits[i]);
                                    }
                                    // If there was a random parenthesis not starting the variable
                                    else if (j > 0)
                                    {
                                        invalid = true;
                                        Log.Warning(Strings.Get("Err_ClauseCharactersBeforeOpenParentheses"), expression, rule.Name, splits[i]);
                                    }
                                    lastOpen = j;
                                }
                                else if (splits[i][j] == ')')
                                {
                                    // If we've seen a close before update last
                                    if (lastClose != -1 && j - lastClose != 1)
                                    {
                                        invalid = true;
                                        Log.Warning(Strings.Get("Err_ClauseCharactersBetweenClosedParentheses"), expression, rule.Name, splits[i]);
                                    }
                                    lastClose = j;
                                }
                                else
                                {
                                    // If we've set a close this is invalid because we can't have other characters after it
                                    if (lastClose != -1)
                                    {
                                        invalid = true;
                                        Log.Warning(Strings.Get("Err_ClauseCharactersAfterClosedParentheses"), expression, rule.Name, splits[i]);
                                    }
                                }
                            }

                            var variable = splits[i].Replace("(", "").Replace(")", "");

                            if (variable == "NOT")
                            {
                                if (previouslyNot)
                                {
                                    invalid = true;
                                    Log.Warning(Strings.Get("Err_ClauseMultipleConsecutiveNots"), expression, rule.Name);
                                }
                                else if (splits[i].Contains(")"))
                                {
                                    invalid = true;
                                    Log.Warning(Strings.Get("Err_ClauseCloseParenthesesInNot"), expression, rule.Name, splits[i]);
                                }
                                previouslyNot = true;
                            }
                            else
                            {
                                foundLabels.Add(variable);
                                previouslyNot = false;
                                if (string.IsNullOrWhiteSpace(variable) || !rule.Clauses.Any(x => x.Label == variable))
                                {
                                    invalid = true;
                                    Log.Warning(Strings.Get("Err_ClauseUndefinedLabel"), expression, rule.Name, splits[i].Replace("(", "").Replace(")", ""));
                                }
                                expectingOperator = true;
                            }
                        }
                        //Operator
                        else
                        {
                            // If we can't enum parse the operator
                            if (!Enum.TryParse(typeof(BOOL_OPERATOR), splits[i], out object? op))
                            {
                                invalid = true;
                                Log.Warning(Strings.Get("Err_ClauseInvalidOperator"), expression, rule.Name, splits[i]);
                            }
                            // We don't allow NOT operators to modify other Operators, so we can't allow NOT here
                            else
                            {
                                if (op is BOOL_OPERATOR boolOp && boolOp == BOOL_OPERATOR.NOT)
                                {
                                    invalid = true;
                                    Log.Warning(Strings.Get("Err_ClauseInvalidNotOperator"), expression, rule.Name);
                                }
                            }
                            expectingOperator = false;
                        }
                    }

                    // We should always end on expecting an operator (having gotten a variable)
                    if (!expectingOperator)
                    {
                        invalid = true;
                        Log.Warning(Strings.Get("Err_ClauseEndsWithOperator"), expression, rule.Name);
                    }
                }

                var groupedFoundLabels = foundLabels.GroupBy(x => x);

                // Were all the labels declared in clauses used?
                foreach (var label in rule.Clauses.Select(x => x.Label))
                {
                    if (label is string)
                    {
                        if (!foundLabels.Contains(label))
                        {
                            invalid = true;
                            Log.Warning(Strings.Get("Err_ClauseUnusedLabel"), label, rule.Name);
                        }
                    }
                }

                var justTheLabels = clauseLabels.Select(x => x.Key);
                // If any clause has a label they all must have labels
                if (justTheLabels.Any(x => x is string) && justTheLabels.Any(x => x is null))
                {
                    invalid = true;
                    Log.Warning(Strings.Get("Err_ClauseMissingLabels"), rule.Name);
                }
                // If the clause has an expression it may not have any null labels
                if (rule.Expression != null && justTheLabels.Any(x => x is null))
                {
                    invalid = true;
                    Log.Warning(Strings.Get("Err_ClauseExpressionButMissingLabels"), rule.Name);
                }
            }


            if (invalid)
            {
                Log.Fatal(Strings.Get("Err_RulesInvalid"));
            }
            else
            {
                Log.Information(Strings.Get("RulesVerified"));
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

                return config.DefaultLevels[compareResult.ResultType];
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
                case BOOL_OPERATOR.NOT:
                    return !first;
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

        private static bool Evaluate(string[] splits, Dictionary<Clause, bool> ClauseResults)
        {
            bool current = false;


            var internalIndex = 0;
            var hasNotOperator = splits[0].Replace("(", "").Replace(")", "").Equals(BOOL_OPERATOR.NOT.ToString());

            if (hasNotOperator)
            {
                internalIndex = 1;
            }

            var res = ClauseResults.Where(x => x.Key.Label == splits[internalIndex].Replace("(", "").Replace(")", ""));
            if (!(res.Count() == 1))
            {
                return false;
            }
            if (hasNotOperator)
            {
                current = !res.First().Value;
            }
            else
            {
                current = res.First().Value;
            }

            BOOL_OPERATOR Operator = BOOL_OPERATOR.AND;

            var updated_i = internalIndex + 1;
            var operatorExpected = true;
            for (int i = updated_i; i < splits.Length; i = updated_i)
            {
                if (operatorExpected)
                {
                    Operator = (BOOL_OPERATOR)Enum.Parse(typeof(BOOL_OPERATOR), splits[i]);
                    operatorExpected = false;
                }
                else
                {
                    if (splits[i].StartsWith("("))
                    {
                        //Get the substring closing this paren
                        var matchingParen = FindMatchingParen(splits, i);
                        current = Operate(Operator, current, Evaluate(splits[i..(matchingParen + 1)], ClauseResults));
                        updated_i = matchingParen + 1;
                    }
                    else
                    {
                        internalIndex = i;
                        hasNotOperator = splits[i].Equals(BOOL_OPERATOR.NOT.ToString());

                        if (hasNotOperator)
                        {
                            internalIndex = i + 1;
                            updated_i = i + 2;
                        }

                        res = ClauseResults.Where(x => x.Key.Label == splits[internalIndex].Replace("(", "").Replace(")", ""));
                        if (!(res.Count() == 1))
                        {
                            return false;
                        }
                        if (hasNotOperator)
                        {
                            current = Operate(Operator, current, !res.First().Value);
                        }
                        else
                        {
                            current = Operate(Operator, current, res.First().Value);
                        }
                    }
                    operatorExpected = true;
                }
                updated_i = updated_i == i ? i + 1 : updated_i;
            }

            return current;
        }

        private static (List<string?>, List<KeyValuePair<string, string>>) ObjectToValues(object? obj)
        {
            var valsToCheck = new List<string?>();
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
                valsToCheck.Add(null);
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
                        foreach (var val in valsToCheck)
                        {
                            if (int.TryParse(val, out int valToCheck))
                            {
                                if (valToCheck > int.Parse(clause.Data?[0] ?? $"{int.MaxValue}", CultureInfo.InvariantCulture))
                                {
                                    return true;
                                }
                            }
                        }
                        return false;

                    // If any of the data values are less than the first provided data value
                    case OPERATION.LT:
                        foreach (var val in valsToCheck)
                        {
                            if (int.TryParse(val, out int valToCheck))
                            {
                                if (valToCheck < int.Parse(clause.Data?[0] ?? $"{int.MaxValue}", CultureInfo.InvariantCulture))
                                {
                                    return true;
                                }
                            }
                        }
                        return false;

                    // If any of the regexes match any of the values
                    case OPERATION.REGEX:
                        if (clause.Data is List<string> RegexList)
                        {
                            if (RegexList.Count > 0)
                            {
                                var sb = new StringBuilder();
                                sb.Append("(");
                                foreach (var rgx in RegexList)
                                {
                                    sb.Append(rgx);
                                    sb.Append('|');
                                }
                                sb.Append(")");

                                var built = sb.ToString();

                                if (!RegexCache.ContainsKey(built))
                                {
                                    RegexCache.Add(built, new Regex(built, RegexOptions.Compiled));
                                }

                                if (valsToCheck.Any(x => RegexCache[built].IsMatch(x)))
                                {
                                    return true;
                                }
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
                            if (valsToCheck.Where(x => EndsWithData.Where(y => x is string && x.EndsWith(y, StringComparison.CurrentCulture)).Any()).Any())
                            {
                                return true;
                            }
                        }
                        return false;

                    // Starts with any of the provided data
                    case OPERATION.STARTS_WITH:
                        if (clause.Data is List<string> StartsWithData)
                        {
                            if (valsToCheck.Where(x => StartsWithData.Where(y => x is string && x.StartsWith(y, StringComparison.CurrentCulture)).Any()).Any())
                            {
                                return true;
                            }
                        }
                        return false;

                    case OPERATION.IS_NULL:
                        if (valsToCheck.Count(x => x is null) == valsToCheck.Count())
                        {
                            return true;
                        }
                        return false;

                    case OPERATION.IS_TRUE:
                        foreach (var valToCheck in valsToCheck)
                        {
                            if (bool.TryParse(valToCheck, out bool result))
                            {
                                if (result)
                                {
                                    return true;
                                }
                            }
                        }
                        return false;
                    case OPERATION.IS_BEFORE:
                        var valDateTimes = new List<DateTime>();
                        foreach (var valToCheck in valsToCheck)
                        {
                            if (DateTime.TryParse(valToCheck, out DateTime result))
                            {
                                valDateTimes.Add(result);
                            }
                        }
                        foreach(var data in clause.Data ?? new List<string>())
                        {
                            if (DateTime.TryParse(data, out DateTime result))
                            {
                                if (valDateTimes.Any(x => x.CompareTo(result) < 0))
                                {
                                    return true;
                                }
                            }
                        }
                        return false;
                    case OPERATION.IS_AFTER:
                        valDateTimes = new List<DateTime>();
                        foreach (var valToCheck in valsToCheck)
                        {
                            if (DateTime.TryParse(valToCheck, out DateTime result))
                            {
                                valDateTimes.Add(result);
                            }
                        }
                        foreach (var data in clause.Data ?? new List<string>())
                        {
                            if (DateTime.TryParse(data, out DateTime result))
                            {
                                if (valDateTimes.Any(x => x.CompareTo(result) > 0))
                                {
                                    return true;
                                }
                            }
                        }
                        return false;
                    case OPERATION.IS_EXPIRED:
                        foreach (var valToCheck in valsToCheck)
                        {
                            if (DateTime.TryParse(valToCheck, out DateTime result))
                            {
                                if (valDateTimes.Any(x => x.CompareTo(DateTime.Now) < 0))
                                {
                                    return true;
                                }
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


