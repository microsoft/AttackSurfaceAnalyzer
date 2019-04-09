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
        INVALID_PATH
    }
}