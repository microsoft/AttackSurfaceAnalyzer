// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
function appendDebugMessage(message, remote) {
    $("#debug").add("<div>").html((remote ? "Service: " : "Local: ") + message);
}

function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

var RESULT_TYPE = {
    FILE: 0,
    PORT: 1,
    REGISTRY: 2,
    CERTIFICATE: 3,
    SERVICES: 4,
    USER: 5,
    UNKNOWN: 6
};
var CHANGE_TYPE = {
    CREATED : 0,
    DELETED : 1,
    MODIFIED: 2,
    RENAMED: 3,
    INVALID: 4
}
var RUN_STATUS = {
    NOT_STARTED: 0,
    RUNNING: 1,
    FAILED: 2,
    COMPLETED: 3,
    NO_RESULTS: 4
}
var ERRORS = {
    NONE: 0,
    UNIQUE_ID: 1
}
//There is a better way to do this
function runStatusToString(runStatus) {
    switch (runStatus) {
        case RUN_STATUS.NOT_STARTED:
            return "Not Started"
        case RUN_STATUS.RUNNING:
            return "Running"
        case RUN_STATUS.FAILED:
            return "Failed"
        case RUN_STATUS.COMPLETED:
            return "Completed"
        case RUN_STATUS.NO_RESULTS:
            return "No Results"
    }
}

$.getJSON('Home/CheckAdmin', function (result) {
    if (JSON.parse(result) == true) {
        $("#AdminWarning").hide();
    }
    else {
        $("#AdminWarning").show();
    }
});