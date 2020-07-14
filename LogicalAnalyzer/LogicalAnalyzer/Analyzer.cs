// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using KellermanSoftware.CompareNetObjects;
using Microsoft.CST.LogicalAnalyzer.Utils;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.LogicalAnalyzer
{
    public class Analyzer
    {
        private readonly ConcurrentDictionary<string, Regex> RegexCache = new ConcurrentDictionary<string, Regex>();

        public Analyzer()
        {
        }

        public delegate (bool Processed, object? Result) ParseCustomProperty(object? obj, string index);

        public delegate (bool Processed, IEnumerable<string> valsExtracted, IEnumerable<KeyValuePair<string, string>> dictExtracted) ParseObjectToValues(object? obj);

        public delegate bool OperationDelegate(Clause clause, IEnumerable<string>? valsToCheck, IEnumerable<KeyValuePair<string, string>> dictToCheck);

        public delegate IEnumerable<Violation> ParseClauseForRules(Rule r, Clause c);

        public ParseCustomProperty? CustomPropertyDelegate { get; set; }

        public ParseObjectToValues? CustomObjectToValuesDelegate { get; set; }

        public OperationDelegate? CustomOperationDelegate { get; set; }

        public ParseClauseForRules? CustomOperationValidationDelegate { get; set; }

        /// <summary>
        /// Extracts a value stored at the specified path inside an object. Can crawl into List and
        /// Dictionaries of strings and return any top-level object.
        /// </summary>
        /// <param name="targetObject">The object to parse</param>
        /// <param name="pathToProperty">The path of the property to fetch</param>
        /// <returns></returns>
        public object? GetValueByPropertyString(object? targetObject, string pathToProperty)
        {
            if (pathToProperty is null || targetObject is null)
            {
                return null;
            }
            try
            {
                var pathPortions = pathToProperty.Split('.');

                // We first try to get the first value to get it started
                var value = GetValueByPropertyName(targetObject, pathPortions[0]);

                // For the rest of the path we walk each portion to get the next object
                for (int pathPortionIndex = 1; pathPortionIndex < pathPortions.Length; pathPortionIndex++)
                {
                    if (value == null) { break; }

                    switch (value)
                    {
                        case Dictionary<string, string> stringDict:
                            if (stringDict.TryGetValue(pathPortions[pathPortionIndex], out string? stringValue))
                            {
                                value = stringValue;
                            }
                            else
                            {
                                value = null;
                            }
                            break;

                        case List<string> stringList:
                            if (int.TryParse(pathPortions[pathPortionIndex], out int ArrayIndex) && stringList.Count > ArrayIndex)
                            {
                                value = stringList[ArrayIndex];
                            }
                            else
                            {
                                value = null;
                            }
                            break;

                        default:
                            var res = CustomPropertyDelegate?.Invoke(value, pathPortions[pathPortionIndex]);

                            // If we couldn't do any custom parsing fall back to the default
                            if (!res.HasValue || res.Value.Processed == false)
                            {
                                value = GetValueByPropertyName(value, pathPortions[pathPortionIndex]);
                            }
                            else
                            {
                                value = res.Value.Result;
                            }
                            break;
                    }
                }
                return value;
            }
            catch (Exception e)
            {
                Log.Information("Fetching Field {0} failed from {1} ({2}:{3})", pathToProperty, targetObject.GetType(), e.GetType(), e.Message);
            }
            return null;
        }

        public static void PrintViolations(IEnumerable<Violation> violations)
        {
            if (violations == null) return;
            foreach (var violation in violations)
            {
                Log.Warning(violation.description);
            }
        }

        public string[] GetTags(IEnumerable<Rule> rules, object? before = null, object? after = null)
        {
            var tags = new ConcurrentDictionary<string, byte>();

            Parallel.ForEach(rules, rule =>
            {
                if (!rule.Tags.All(x => tags.Keys.Any(y => y == x)) && Applies(rule, before, after))
                {
                    foreach(var tag in rule.Tags)
                    {
                        tags.TryAdd(tag, 0);
                    }
                }
            });

            return tags.Keys.ToArray();
        }

        public ConcurrentStack<Rule> Analyze(IEnumerable<Rule> rules, object? before = null, object? after = null)
        {
            var results = new ConcurrentStack<Rule>();

            if (before is null && after is null)
            {
                return results;
            }

            Parallel.ForEach(rules, rule =>
            {
                if (Applies(rule, before, after))
                {
                    results.Push(rule);
                }
            });

            return results;
        }

        public bool Applies(Rule rule, object? before = null, object? after = null)
        {
            if ((before != null || after != null) && rule != null)
            {
                var sample = before is null ? after : before;

                // Does the name of this class match the Target in the rule?
                // Or has no target been specified (match all)
                if (rule.Target is null || (sample?.GetType().Name.Equals(rule.Target, StringComparison.InvariantCultureIgnoreCase) ?? false))
                {
                    // If the expression is null the default is that all clauses must be true
                    // If we have no clauses .All will still match
                    if (rule.Expression is null)
                    {
                        if (rule.Clauses.All(x => AnalyzeClause(x, before, after)))
                        {
                            return true;
                        }
                    }
                    // Otherwise we evaluate the expression
                    else
                    {
                        if (Evaluate(rule.Expression.Split(' '), rule.Clauses, before, after))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }
            else
            {
                throw new NullReferenceException();
            }
        }

        /// <summary>
        /// Determines if there are any problems with the provided rule.
        /// </summary>
        /// <param name="rule">The rule to parse.</param>
        /// <returns>True if there are no issues.</returns>
        public bool IsRuleValid(Rule rule) => !EnumerateRuleIssues(new Rule[] { rule }).Any();

        /// <summary>
        /// Verifies the provided rules and provides a list of issues with the rules.
        /// </summary>
        /// <param name="rules"></param>
        /// <returns>List of issues with the rules.</returns>
        public IEnumerable<Violation> EnumerateRuleIssues(IEnumerable<Rule> rules)
        {
            foreach (Rule rule in rules ?? Array.Empty<Rule>())
            {
                var clauseLabels = rule.Clauses.GroupBy(x => x.Label);

                // If clauses have duplicate names
                var duplicateClauses = clauseLabels.Where(x => x.Key != null && x.Count() > 1);
                foreach (var duplicateClause in duplicateClauses)
                {
                    yield return new Violation(string.Format(Strings.Get("Err_ClauseDuplicateName"), rule.Name, duplicateClause.Key ?? string.Empty), rule, duplicateClause.AsEnumerable().ToArray());
                }

                // If clause label contains illegal characters
                foreach (var clause in rule.Clauses)
                {
                    if (clause.Label is string label)
                    {
                        if (label.Contains(" ") || label.Contains("(") || label.Contains(")"))
                        {
                            yield return new Violation(string.Format(Strings.Get("Err_ClauseInvalidLabel"), rule.Name, label), rule, clause);
                        }
                    }
                    switch (clause.Operation)
                    {
                        case OPERATION.EQ:
                        case OPERATION.NEQ:
                            if ((clause.Data?.Count == null || clause.Data?.Count == 0))
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseNoData"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            if (clause.DictData != null || clause.DictData?.Count > 0)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseDictDataUnexpected"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture), clause.Operation.ToString()), rule, clause);
                            }
                            break;

                        case OPERATION.CONTAINS:
                        case OPERATION.CONTAINS_ANY:
                            if ((clause.Data?.Count == null || clause.Data?.Count == 0) && (clause.DictData?.Count == null || clause.DictData?.Count == 0))
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseNoDataOrDictData"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            if ((clause.Data is List<string> list && list.Count > 0) && (clause.DictData is List<KeyValuePair<string, string>> dictList && dictList.Count > 0))
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseBothDataDictData"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            break;

                        case OPERATION.ENDS_WITH:
                        case OPERATION.STARTS_WITH:
                            if (clause.Data?.Count == null || clause.Data?.Count == 0)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseNoData"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            if (clause.DictData != null || clause.DictData?.Count > 0)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseDictDataUnexpected"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture), clause.Operation.ToString()), rule, clause);
                            }
                            break;

                        case OPERATION.GT:
                        case OPERATION.LT:
                            if (clause.Data?.Count == null || clause.Data is List<string> clauseList && (clauseList.Count != 1 || !int.TryParse(clause.Data.First(), out int _)))
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseExpectedInt"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            if (clause.DictData != null || clause.DictData?.Count > 0)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseDictDataUnexpected"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture), clause.Operation.ToString()), rule, clause);
                            }
                            break;

                        case OPERATION.REGEX:
                            if (clause.Data?.Count == null || clause.Data?.Count == 0)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseNoData"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            else if (clause.Data is List<string> regexList)
                            {
                                foreach (var regex in regexList)
                                {
                                    if (!Helpers.IsValidRegex(regex))
                                    {
                                        yield return new Violation(string.Format(Strings.Get("Err_ClauseInvalidRegex"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture), regex), rule, clause);
                                    }
                                }
                            }
                            if (clause.DictData != null || clause.DictData?.Count > 0)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseDictDataUnexpected"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture), clause.Operation.ToString()), rule, clause);
                            }
                            break;

                        case OPERATION.IS_NULL:
                        case OPERATION.IS_TRUE:
                        case OPERATION.IS_EXPIRED:
                        case OPERATION.WAS_MODIFIED:
                            if (!(clause.Data?.Count == null || clause.Data?.Count == 0))
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseRedundantData"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            else if (!(clause.DictData?.Count == null || clause.DictData?.Count == 0))
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseRedundantDictData"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            break;

                        case OPERATION.IS_BEFORE:
                        case OPERATION.IS_AFTER:
                            if (clause.Data?.Count == null || clause.Data is List<string> clauseList2 && (clauseList2.Count != 1 || !DateTime.TryParse(clause.Data.First(), out DateTime _)))
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseExpectedDateTime"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            if (clause.DictData != null || clause.DictData?.Count > 0)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseDictDataUnexpected"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture), clause.Operation.ToString()), rule, clause);
                            }
                            break;

                        case OPERATION.CONTAINS_KEY:
                            if (clause.DictData != null)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseUnexpectedDictData"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            if (clause.Data == null || clause.Data?.Count == 0)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseMissingListData"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            break;

                        case OPERATION.CUSTOM:
                            if (clause.CustomOperation == null)
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseMissingCustomOperation"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture)), rule, clause);
                            }
                            if (CustomOperationValidationDelegate != null)
                            {
                                foreach (var violation in CustomOperationValidationDelegate(rule, clause))
                                {
                                    yield return violation;
                                }
                            }
                            break;

                        case OPERATION.DOES_NOT_CONTAIN:
                        case OPERATION.DOES_NOT_CONTAIN_ALL:
                        default:
                            yield return new Violation(string.Format(Strings.Get("Err_ClauseUnsuppportedOperator"), rule.Name, clause.Label ?? rule.Clauses.IndexOf(clause).ToString(CultureInfo.InvariantCulture), clause.Operation.ToString()), rule, clause);
                            break;
                    }
                }

                var foundLabels = new List<string>();

                if (rule.Expression is string expression)
                {
                    // Are parenthesis balanced Are spaces correct Are all variables defined by
                    // clauses? Are variables and operators alternating?
                    var splits = expression.Split(' ');
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
                            yield return new Violation(string.Format(Strings.Get("Err_ClauseUnbalancedParentheses"), expression, rule.Name), rule);
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
                                        yield return new Violation(string.Format(Strings.Get("Err_ClauseParenthesisInLabel"), expression, rule.Name, splits[i]), rule);
                                    }
                                    // If there were any characters between open parenthesis
                                    if (j - lastOpen != 1)
                                    {
                                        yield return new Violation(string.Format(Strings.Get("Err_ClauseCharactersBetweenOpenParentheses"), expression, rule.Name, splits[i]), rule);
                                    }
                                    // If there was a random parenthesis not starting the variable
                                    else if (j > 0)
                                    {
                                        yield return new Violation(string.Format(Strings.Get("Err_ClauseCharactersBeforeOpenParentheses"), expression, rule.Name, splits[i]), rule);
                                    }
                                    lastOpen = j;
                                }
                                else if (splits[i][j] == ')')
                                {
                                    // If we've seen a close before update last
                                    if (lastClose != -1 && j - lastClose != 1)
                                    {
                                        yield return new Violation(string.Format(Strings.Get("Err_ClauseCharactersBetweenClosedParentheses"), expression, rule.Name, splits[i]), rule);
                                    }
                                    lastClose = j;
                                }
                                else
                                {
                                    // If we've set a close this is invalid because we can't have
                                    // other characters after it
                                    if (lastClose != -1)
                                    {
                                        yield return new Violation(string.Format(Strings.Get("Err_ClauseCharactersAfterClosedParentheses"), expression, rule.Name, splits[i]), rule);
                                    }
                                }
                            }

                            var variable = splits[i].Replace("(", "").Replace(")", "");

                            if (variable == "NOT")
                            {
                                if (previouslyNot)
                                {
                                    yield return new Violation(string.Format(Strings.Get("Err_ClauseMultipleConsecutiveNots"), expression, rule.Name), rule);
                                }
                                else if (splits[i].Contains(")"))
                                {
                                    yield return new Violation(string.Format(Strings.Get("Err_ClauseCloseParenthesesInNot"), expression, rule.Name, splits[i]), rule);
                                }
                                previouslyNot = true;
                            }
                            else
                            {
                                foundLabels.Add(variable);
                                previouslyNot = false;
                                if (string.IsNullOrWhiteSpace(variable) || !rule.Clauses.Any(x => x.Label == variable))
                                {
                                    yield return new Violation(string.Format(Strings.Get("Err_ClauseUndefinedLabel"), expression, rule.Name, splits[i].Replace("(", "").Replace(")", "")), rule);
                                }
                                expectingOperator = true;
                            }
                        }
                        //Operator
                        else
                        {
                            // If we can't enum parse the operator
                            if (!Enum.TryParse<BOOL_OPERATOR>(splits[i], out BOOL_OPERATOR op))
                            {
                                yield return new Violation(string.Format(Strings.Get("Err_ClauseInvalidOperator"), expression, rule.Name, splits[i]), rule);
                            }
                            // We don't allow NOT operators to modify other Operators, so we can't
                            // allow NOT here
                            else
                            {
                                if (op is BOOL_OPERATOR boolOp && boolOp == BOOL_OPERATOR.NOT)
                                {
                                    yield return new Violation(string.Format(Strings.Get("Err_ClauseInvalidNotOperator"), expression, rule.Name), rule);
                                }
                            }
                            expectingOperator = false;
                        }
                    }

                    // We should always end on expecting an operator (having gotten a variable)
                    if (!expectingOperator)
                    {
                        yield return new Violation(string.Format(Strings.Get("Err_ClauseEndsWithOperator"), expression, rule.Name), rule);
                    }
                }

                // Were all the labels declared in clauses used?
                foreach (var label in rule.Clauses.Select(x => x.Label))
                {
                    if (label is string)
                    {
                        if (!foundLabels.Contains(label))
                        {
                            yield return new Violation(string.Format(Strings.Get("Err_ClauseUnusedLabel"), label, rule.Name), rule);
                        }
                    }
                }

                var justTheLabels = clauseLabels.Select(x => x.Key);
                // If any clause has a label they all must have labels
                if (justTheLabels.Any(x => x is string) && justTheLabels.Any(x => x is null))
                {
                    yield return new Violation(string.Format(Strings.Get("Err_ClauseMissingLabels"), rule.Name), rule);
                }
                // If the clause has an expression it may not have any null labels
                if (rule.Expression != null && justTheLabels.Any(x => x is null))
                {
                    yield return new Violation(string.Format(Strings.Get("Err_ClauseExpressionButMissingLabels"), rule.Name), rule);
                }
            }
        }

        protected bool AnalyzeClause(Clause clause, object? before = null, object? after = null)
        {
            if (clause == null || (before == null && after == null))
            {
                return false;
            }
            try
            {
                // Support bare objects
                if (clause.Field is string)
                {
                    after = GetValueByPropertyString(after, clause.Field);
                    before = GetValueByPropertyString(before, clause.Field);
                }


                var typeHolder = before is null ? after : before;

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
                                if (ContainsData.All(y => dictToCheck.Any((x) => x.Key == y.Key && x.Value == y.Value)))
                                {
                                    return true;
                                }
                            }
                        }
                        else if (valsToCheck.Any())
                        {
                            if (clause.Data is List<string> ContainsDataList)
                            {
                                // If we are dealing with an array on the object side
                                if (typeHolder is List<string>)
                                {
                                    if (ContainsDataList.All(x => valsToCheck.Contains(x)))
                                    {
                                        return true;
                                    }
                                }
                                // If we are dealing with a single string we do a .Contains instead
                                else if (typeHolder is string)
                                {
                                    if (clause.Data.All(x => valsToCheck.First()?.Contains(x) ?? false))
                                    {
                                        return true;
                                    }
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
                                    if (dictToCheck.Any(x => x.Key == value.Key && x.Value == value.Value))
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
                                if (typeHolder is List<string>)
                                {
                                    if (ContainsDataList.Any(x => valsToCheck.Contains(x)))
                                    {
                                        return true;
                                    }
                                }
                                // If we are dealing with a single string we do a .Contains instead
                                else if (typeHolder is string)
                                {
                                    if (clause.Data.Any(x => valsToCheck.First()?.Contains(x) ?? false))
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                        return false;

                    // If any of the data values are greater than the first provided clause value We
                    // ignore all other clause values
                    case OPERATION.GT:
                        foreach (var val in valsToCheck)
                        {
                            if (int.TryParse(val, out int valToCheck))
                            {
                                if (int.TryParse(clause.Data?[0], out int dataValue))
                                {
                                    if (valToCheck > dataValue)
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                        return false;

                    // If any of the data values are less than the first provided clause value We
                    // ignore all other clause values
                    case OPERATION.LT:
                        foreach (var val in valsToCheck)
                        {
                            if (int.TryParse(val, out int valToCheck))
                            {
                                if (int.TryParse(clause.Data?[0], out int dataValue))
                                {
                                    if (valToCheck < dataValue)
                                    {
                                        return true;
                                    }
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
                                var built = string.Join('|', RegexList);

                                if (!RegexCache.ContainsKey(built))
                                {
                                    try
                                    {
                                        RegexCache.TryAdd(built, new Regex(built, RegexOptions.Compiled));
                                    }
                                    catch (ArgumentException)
                                    {
                                        Log.Warning("InvalidArgumentException when analyzing clause {0}. Regex {1} is invalid and will be skipped.", clause.Label, built);
                                        RegexCache.TryAdd(built, new Regex("", RegexOptions.Compiled));
                                    }
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
                        CompareLogic compareLogic = new CompareLogic();

                        ComparisonResult comparisonResult = compareLogic.Compare(before, after);

                        return !comparisonResult.AreEqual;

                    // Ends with any of the provided data
                    case OPERATION.ENDS_WITH:
                        if (clause.Data is List<string> EndsWithData)
                        {
                            if (valsToCheck.Any(x => EndsWithData.Any(y => x is string && x.EndsWith(y, StringComparison.CurrentCulture))))
                            {
                                return true;
                            }
                        }
                        return false;

                    // Starts with any of the provided data
                    case OPERATION.STARTS_WITH:
                        if (clause.Data is List<string> StartsWithData)
                        {
                            if (valsToCheck.Any(x => StartsWithData.Any(y => x is string && x.StartsWith(y, StringComparison.CurrentCulture))))
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
                        foreach (var data in clause.Data ?? new List<string>())
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
                                if (result.CompareTo(DateTime.Now) < 0)
                                {
                                    return true;
                                }
                            }
                        }
                        return false;

                    case OPERATION.CONTAINS_KEY:
                        return dictToCheck.Any(x => clause.Data.Any(y => x.Key == y));

                    case OPERATION.CUSTOM:
                        if (CustomOperationDelegate is null)
                        {
                            Log.Debug("Custom operation hit but {0} isn't set.", nameof(CustomOperationDelegate));
                            return false;
                        }
                        else
                        {
                            return CustomOperationDelegate.Invoke(clause, valsToCheck, dictToCheck);
                        }

                    default:
                        Log.Debug("Unimplemented operation {0}", clause.Operation);
                        return false;
                }
            }
            catch (Exception e)
            {
                Log.Debug(e, $"Hit while parsing {JsonConvert.SerializeObject(clause)} onto ({JsonConvert.SerializeObject(before)},{JsonConvert.SerializeObject(after)})");
            }

            return false;
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

        private static object? GetValueByPropertyName(object? obj, string? propertyName) => obj?.GetType().GetProperty(propertyName ?? string.Empty)?.GetValue(obj);

        private (List<string>, List<KeyValuePair<string, string>>) ObjectToValues(object? obj)
        {
            List<string> valsToCheck = new List<string>();
            List<KeyValuePair<string, string>> dictToCheck = new List<KeyValuePair<string, string>>();
            if (obj != null)
            {
                try
                {
                    if (obj is List<string> stringList)
                    {
                        valsToCheck.AddRange(stringList);
                    }
                    else if (obj is Dictionary<string, string> dictString)
                    {
                        dictToCheck = dictString.ToList();
                    }
                    else if (obj is Dictionary<string, List<string>> dict)
                    {
                        dictToCheck = new List<KeyValuePair<string, string>>();
                        foreach (var list in dict.ToList())
                        {
                            foreach (var entry in list.Value)
                            {
                                dictToCheck.Add(new KeyValuePair<string, string>(list.Key, entry));
                            }
                        }
                    }
                    else if (obj is List<KeyValuePair<string, string>> listKvp)
                    {
                        dictToCheck = listKvp;
                    }
                    else
                    {
                        var res = CustomObjectToValuesDelegate?.Invoke(obj);
                        if (res.HasValue && res.Value.Processed == true)
                        {
                            (valsToCheck, dictToCheck) = (res.Value.valsExtracted.ToList(), res.Value.dictExtracted.ToList());
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
                }
                catch (Exception e)
                {
                    //Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                    //ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                    //AsaTelemetry.TrackEvent("ApplyDeletedModifiedException", ExceptionEvent);
                }
            }

            return (valsToCheck, dictToCheck);
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

        private bool Evaluate(string[] splits, List<Clause> Clauses, object? before, object? after)
        {
            bool current = false;

            var invertNextStatement = false;
            var operatorExpected = false;

            BOOL_OPERATOR Operator = BOOL_OPERATOR.OR;

            var updated_i = 0;

            for (int i = 0; i < splits.Length; i = updated_i)
            {
                if (operatorExpected)
                {
                    Operator = (BOOL_OPERATOR)Enum.Parse(typeof(BOOL_OPERATOR), splits[i]);
                    operatorExpected = false;
                    updated_i = i + 1;
                }
                else
                {
                    if (splits[i].StartsWith("("))
                    {
                        //Get the substring closing this paren
                        var matchingParen = FindMatchingParen(splits, i);

                        // First remove the parenthesis from the beginning and end
                        splits[i] = splits[i][1..];
                        splits[matchingParen] = splits[matchingParen][0..^1];

                        var shortcut = TryShortcut(current, Operator);

                        if (shortcut.CanShortcut)
                        {
                            current = shortcut.Value;
                        }
                        else
                        {
                            // Recursively evaluate the contents of the parentheses
                            var next = Evaluate(splits[i..(matchingParen + 1)], Clauses, before, after);

                            next = invertNextStatement ? !next : next;

                            current = Operate(Operator, current, next);
                        }

                        updated_i = matchingParen + 1;
                        invertNextStatement = false;
                        operatorExpected = true;
                    }
                    else
                    {
                        if (splits[i].Equals(BOOL_OPERATOR.NOT.ToString()))
                        {
                            invertNextStatement = true;
                            operatorExpected = false;
                        }
                        else
                        {
                            // Ensure we have exactly 1 matching clause defined
                            var res = Clauses.Where(x => x.Label == splits[i].Replace("(", "").Replace(")", ""));
                            if (!(res.Count() == 1))
                            {
                                return false;
                            }

                            var clause = res.First();

                            var shortcut = TryShortcut(current, Operator);

                            if (shortcut.CanShortcut)
                            {
                                current = shortcut.Value;
                            }
                            else
                            {
                                bool next;

                                next = AnalyzeClause(res.First(), before, after);

                                next = invertNextStatement ? !next : next;

                                current = Operate(Operator, current, next);
                            }

                            invertNextStatement = false;
                            operatorExpected = true;
                        }
                        updated_i = i + 1;
                    }
                }
            }
            return current;
        }

        public static (bool CanShortcut, bool Value) TryShortcut(bool current, BOOL_OPERATOR operation)
        {
            // If either argument of an AND statement is false, or either argument of a
            // NOR statement is true, the result is always false and we can optimize
            // away evaluation of next
            if ((operation == BOOL_OPERATOR.AND && current == false) ||
                (operation == BOOL_OPERATOR.NOR && current == true))
            {
                return (true, false);
            }
            // If either argument of an NAND statement is false, or either argument of
            // an OR statement is true, the result is always true and we can optimize
            // away evaluation of next
            if ((operation == BOOL_OPERATOR.OR && current == true) ||
                (operation == BOOL_OPERATOR.NAND && current == false))
            {
                return (true, true);
            }
            return (false, false);
        }
    }
}