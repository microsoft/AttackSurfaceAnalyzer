// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.ObjectTypes
{
    public enum RESULT_TYPE {
        FILE,
        PORT,
        REGISTRY,
        CERTIFICATE,
        SERVICES,
        USER,
        UNKNOWN
    };

     public enum CHANGE_TYPE
    {
        CREATED,
        DELETED,
        MODIFIED,
        RENAMED,
        INVALID
    }

    public enum RUN_STATUS
    {
        NOT_STARTED,
        RUNNING,
        FAILED,
        COMPLETED,
        NO_RESULTS
    }

    public enum ERRORS
    {
        NONE,
        UNIQUE_ID,
        INVALID_PATH,
        ALREADY_RUNNING,
        NO_COLLECTORS
    }

    public enum DLLCHARACTERISTICS
    {
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
        IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
        IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
        IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
        IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
    }

    // These need better names. But the heirarchy of these makes sense to me as a model.
    // These are flags that can be defined in an analyze.json to arrange output by importance.
    public enum ANALYSIS_RESULT_TYPE
    {
        VERBOSE,
        DEBUG,
        INFORMATION,
        WARNING,
        ERROR,
        FATAL
    }

    public enum OPERATION
    {
        REGEX,
        EQ,
        NEQ,
        LT,
        GT,
        CONTAINS
    }
}