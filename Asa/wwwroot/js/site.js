// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
"use strict";

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
    UNKNOWN: 0,
    FILE: 1,
    PORT: 2,
    REGISTRY: 3,
    CERTIFICATE: 4,
    SERVICES: 5,
    USER: 6,
    GROUP: 7,
    FIREWALL: 8,
    COM: 9,
    LOG: 10
};
var CHANGE_TYPE = {
    INVALID: 0,
    CREATED: 1,
    DELETED: 2,
    MODIFIED: 3,
    RENAMED: 4,
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
    UNIQUE_ID: 1,
    INVALID_PATH: 2,
    ALREADY_RUNNING: 3,
    NO_COLLECTORS: 4
}
var ANALYSIS_RESULT_TYPE = {
    NONE: 0,
    VERBOSE: 1,
    DEBUG: 2,
    INFORMATION: 3,
    WARNING: 4,
    ERROR: 5,
    FATAL: 6
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

var l = function (string) {
    return string.toLocaleString();
};

function isIE() {
    var ua = window.navigator.userAgent;

    var msie = ua.indexOf('MSIE ');
    var trident = ua.indexOf('Trident/');
    var edge = ua.indexOf('Edge/');

    if (msie > 0 || trident > 0 || edge > 0) {
        return true
    }

    return false;
}

