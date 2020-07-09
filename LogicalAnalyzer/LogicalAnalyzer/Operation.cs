namespace Microsoft.CST.LogicalAnalyzer
{
    /// <summary>
    ///     Operations available for Analysis rules.
    /// </summary>
    public enum OPERATION
    {
        /// <summary>
        ///     Generates regular expressions from the Data list provided and tests them against the specified
        ///     field. If any match it is a success.
        /// </summary>
        REGEX,

        /// <summary>
        ///     Checks that any value in the Data list or DictData dictionary have a match in the specified
        ///     field's object as appropriate.
        /// </summary>
        EQ,

        /// <summary>
        ///     Checks that any value in the Data list or DictData dictionary does not have a match in the
        ///     specified field's object as appropriate.
        /// </summary>
        NEQ,

        /// <summary>
        ///     Checks whether the specified fields value when parsed as an int is less than first value in
        ///     the Data list as Parsed as an Int
        /// </summary>
        LT,

        /// <summary>
        ///     Checks whether the specified fields value when parsed as an int is greater than first value in
        ///     the Data list as Parsed as an Int
        /// </summary>
        GT,

        /// <summary>
        ///     Checks if the specified fields values contain all of the data in the Data list or DictData
        ///     dictionary as appropriate for the field.
        /// </summary>
        CONTAINS,

        /// <summary>
        ///     Checks if the specified fields values does not contain any of the data in the Data list or
        ///     DictData dictionary as appropriate for the field.
        /// </summary>
        DOES_NOT_CONTAIN,

        /// <summary>
        ///     Checks if the specified field was modified between the two runs.
        /// </summary>
        WAS_MODIFIED,

        /// <summary>
        ///     Checks if the specified field ends with any of the strings in the Data list.
        /// </summary>
        ENDS_WITH,

        /// <summary>
        ///     Checks if the specified field starts with any of the strings in the Data list.
        /// </summary>
        STARTS_WITH,

        /// <summary>
        ///     Checks if the specified fields values contain any of the data in the Data list or DictData
        ///     dictionary as appropriate for the field.
        /// </summary>
        CONTAINS_ANY,

        /// <summary>
        ///     Checks if the specified fields values does not contain all of the data in the Data list or
        ///     DictData dictionary as appropriate for the field.
        /// </summary>
        DOES_NOT_CONTAIN_ALL,

        /// <summary>
        ///     Checks if the specified field is null in both runs.
        /// </summary>
        IS_NULL,

        /// <summary>
        ///     Checks if the specified field is true in either run.
        /// </summary>
        IS_TRUE,

        /// <summary>
        ///     Checks if the specified field, as parsed as time, is before the time specified in the first
        ///     entry of the Data list
        /// </summary>
        IS_BEFORE,

        /// <summary>
        ///     Checks if the specified field, as parsed as time, is after the time specified in the first
        ///     entry of the Data list
        /// </summary>
        IS_AFTER,

        /// <summary>
        ///     Checks if the specified field, as parsed as time, is before DateTime.Now.
        /// </summary>
        IS_EXPIRED,

        /// <summary>
        ///     Checks if the field, if a dictionary, contains the specified key
        /// </summary>
        CONTAINS_KEY,

        /// <summary>
        ///     Specifies that a custom operation has been specified
        /// </summary>
        CUSTOM
    }
}
