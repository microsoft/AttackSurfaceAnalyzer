// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
"use strict";

var resultOffset = 0;
var monitorResultOffset = 0;

$('#AnalyzeLink').addClass('active');

var ScanTypeGroup = $('input[type=radio][name=ScanType]');
$('.results').hide();

ScanTypeGroup.change(function () {
    $('.scan').toggle(ScanTypeGroup.filter(':checked').val() === 'Static');
    $('.monitor').toggle(ScanTypeGroup.filter(':checked').val() === 'Live');
    ResetResults();
}).change();

$("#SelectedMonitorRunId").change(function () {
    monitorResultOffset = 0;
    GetMonitorResults($('input[name=MonitorResultType]:checked').val(), monitorResultOffset, 100);
});

$("#DirectorySelector").change(function () {
    $("#DirectoryPath").val($('#DirectorySelector')[0].files[0].path);
});

$("#DirectorySelectorMonitor").change(function () {
    $("#DirectoryPathMonitor").val($('#DirectorySelectorMonitor')[0].files[0].path);
});

var ResultTypeGroup = $('input[type=radio][name=ResultType]');

ResultTypeGroup.change(function () {
    $('.results').hide();
    resultOffset = 0;
    $("#ExportSelection").attr('disabled', false);
    GetResults($('input[name=ResultType]:checked').val(), resultOffset, 100);
    switch (parseInt(ResultTypeGroup.filter(':checked').val())) {
        case RESULT_TYPE.FILE:
            $('.files').show();
            break;
        case RESULT_TYPE.PORT:
            $('.ports').show();
            break;
        case RESULT_TYPE.REGISTRY:
            $('.registry').show();
            break;
        case RESULT_TYPE.CERTIFICATE:
            $('.certificates').show();
            break;
        case RESULT_TYPE.SERVICE:
            $('.services').show();
            break;
        case RESULT_TYPE.USER:
            $('.users').show();
            break;
        case RESULT_TYPE.GROUP:
            $('.groups').show();
            break;
        case RESULT_TYPE.FIREWALL:
            $('.firewall').show();
            break;
        case RESULT_TYPE.COM:
            $('.com').show();
            break;
    }
});

$('#SelectedBaseRunId').change(function () { ResetResults(); });
$('#SelectedCompareRunId').change(function () { ResetResults(); });

$("#RunAnalysisButton").click(function () {
    ResetResults();
    DisableCollectionFields();

    appendDebugMessage("Button Clicked", false);
    if ($("#SelectedBaseRunId").value == "" || $("#SelectedCompareRunId").val() == "") {
        SetStatus("Must select runs.");
        EnableCollectionFields();
    }
    else if ($("#SelectedBaseRunId").val() == $("#SelectedCompareRunId").val()) {
        SetStatus("Must select different runs.");
        EnableCollectionFields();
    }
    else {
        var compare = { 'first_id': $('#SelectedBaseRunId').val(), 'second_id': $('#SelectedCompareRunId').val() };
        $.getJSON('RunAnalysis', compare, function (result) {
            SetStatus(result);
        });

        setTimeout(GetComparators, 500);
    }
});

$("#FetchResultsButton").click(function () {
    resultOffset = resultOffset + 100;
    GetResults($('input[name=ResultType]:checked').val(), resultOffset, 100);
});

$("#RunMonitorAnalysisButton").click(function () {
    monitorResultOffset = monitorResultOffset + 100;
    GetMonitorResults($('input[name=MonitorResultType]:checked').val(), monitorResultOffset, 100);
});

$('#ExportResultsButton').click(ExportToExcel);
$('#ExportMonitorResults').click(ExportMonitorResults);

function ResetResults() {
    $('.results').hide();
    $('input[name=ResultType]').prop('checked', false);
    $('input[name=ResultType]').prop('disabled', true);
    $('tbody').empty();
    $('#CountStatus').empty();
    $('#CompareStatus').empty();
    $('.ResultManipulationButton').prop('disabled', true);
}

function SetStatus(status) {
    $('#Status').empty();
    $('#Status').append(status);
}

function SetMonitorStatus(status) {
    $('#MonitorStatus').empty();
    $('#MonitorStatus').append(status);
}

function GetComparators() {
    $.getJSON('GetComparators', function (result) {
        var data = JSON.parse(result);
        var keepChecking = false;
        var icon;
        $('#CompareStatus').empty();
        $.each(data, function (key, value) {
            if (value === RUN_STATUS.RUNNING) {
                keepChecking = true;
                icon = '<i class="fas fa-cog fa-spin"></i>  ';
            }
            else if (value === RUN_STATUS.COMPLETED) {
                icon = '<i class="far fa-check-circle" style="color:green"></i>  ';
            }
            else if (value === RUN_STATUS.NOT_STARTED) {
                icon = '<i class="fas fa-cog"></i>  ';
            }
            else if (value === RUN_STATUS.NO_RESULTS) {
                icon = '<i class="fas fa-level-down-alt"></i>  ';
            }
            else {
                icon = '<i class="fas fa-exclamation-triangle"></i>  ';
            }
            $('#CompareStatus').append($('<div/>', { html: icon + key + ' is ' + runStatusToString(value), class: 'scan' }));
        });
        if (keepChecking) {
            DisableCollectionFields();
            setTimeout(GetComparators, 500);
        }
        else {
            EnableCollectionFields();
            GetResultTypes();
        }
    });
}

function DisableCollectionFields() {
    $("#RunAnalysisButton").prop("disabled", true);
    $('#SelectedBaseRunId').prop('disabled', true);
    $('#SelectedCompareRunId').prop('disabled', true);
    $('#SelectedResultId').prop('disabled', true);
    $(".ScanType").prop('disabled', true);
    $('input[name=ExportQuantity]').prop('disabled', true);
}

function EnableCollectionFields() {
    $("#RunAnalysisButton").prop("disabled", false);
    $('#SelectedBaseRunId').prop('disabled', false);
    $('#SelectedCompareRunId').prop('disabled', false);
    $('#SelectedResultId').prop('disabled', false);
    $(".ScanType").prop('disabled', false);
}

function GetResultTypes() {
    var data = { 'BaseId': $('#SelectedBaseRunId').val(), 'CompareId': $('#SelectedCompareRunId').val() };

    $.getJSON('GetResultTypes', data, function(result) {
        if ((result.File || result.Port || result.Certificate || result.Service || result.Registry || result.User || result.Firewall || result.Com) == false) {
            SetStatus("The two runs selected have no common collectors.");
        } else {
            $("#ExportResultsButton").attr('disabled', false);
        }
        $('#FileRadio').attr('disabled', (result.File) ? false : true);
        $('#PortRadio').attr('disabled', (result.Port) ? false : true);
        $('#CertificateRadio').attr('disabled', (result.Certificate) ? false : true);
        $('#ServiceRadio').attr('disabled', (result.Service) ? false : true);
        $('#RegistryRadio').attr('disabled', (result.Registry) ? false : true);
        $('#UserRadio').attr('disabled', (result.User) ? false : true);
        $('#FirewallRadio').attr('disabled', (result.Firewall) ? false : true);
        $('#ComRadio').attr('disabled', (result.ComObject) ? false : true);
    });
}

function UpdateNumResults(total, offset, requested, actual) {
    $('#CountStatus').empty();
    if (actual == 0) {
        $("#CountStatus").append(l("%Error.NoDifference"));
    }
    else {
        $("#CountStatus").append(l("%Showing") + (offset + 1) + " - " + (offset + actual) + l("%Results") + total + l("%TotalRecords"));
    }
}

function UpdateMonitorNumResults(total, offset, requested, actual) {
    $('#MonitorCountStatus').empty();
    if (actual == 0) {
        $("#CountStatus").append(l("%Error.NoDifference"));
    }
    else {
        $("#MonitorCountStatus").append(l("%Showing ") + (offset + 1) + " - " + (offset + actual) + l("%Results") + total + l("%TotalRecords"));
    }
}

function GetResults(type, offset, number) {
    var data = { 'BaseId': $('#SelectedBaseRunId').val(), 'CompareId': $('#SelectedCompareRunId').val(), 'ResultType': type, 'Offset': offset, 'NumResults': number };
    $.getJSON('GetResults', data, function (results) {
        var obj = JSON.parse(results);
        UpdateNumResults(obj.TotalCount, obj.Offset, obj.Requested, obj.Actual);

        // Enable only if we have more results to fetch
        $("#FetchResultsButton").attr('disabled', (obj.TotalCount <= obj.Offset + obj.Actual));

        var objs = obj.Results;
        $('tbody').empty();
        for (var i = 0; i < objs.length; i++) {
            InsertIntoTable(objs[i]);
        }
        $('.resultTableRow').click(function () {
            $('#' + this.id + "_expanded").slideToggle();
            var arrow = $('#' + this.id + '_expansion_arrow');
            if (arrow.hasClass('fa-caret-right')) {
                arrow.removeClass('fa-caret-right');
                arrow.addClass('fa-caret-down');
            }
            else {
                arrow.removeClass('fa-caret-down');
                arrow.addClass('fa-caret-right');
            }
        });
        $('.resultTableExpanded').click(function () {
            $('#' + this.id).slideToggle();
        });
    });
}

function GetMonitorResults(type, offset, number) {
    var data = { 'RunId': $('#SelectedMonitorRunId').val(), 'ResultType': type, 'Offset': offset, 'NumResults': number };
    $.getJSON('GetMonitorResults', data, function (results) {
        var obj = JSON.parse(results);
        UpdateMonitorNumResults(obj.TotalCount, obj.Offset, obj.Requested, obj.Actual);

        // Disable the button if we have no more results
        $("#RunMonitorAnalysisButton").attr('disabled', (obj.TotalCount <= obj.Offset + obj.Actual));
        $("#ExportMonitorResults").prop('disabled', false);

        var objs = obj.Results;
        $('tbody').empty();
        for (var i = 0; i < objs.length; i++) {
            InsertIntoMonitorTable(objs[i]);
        }
    });
}

function ChangeTypeToString(change_type) {
    switch (change_type) {
        case CHANGE_TYPE.DELETED:
            return l("%Deleted");
        case CHANGE_TYPE.CREATED:
            return l("%Created");
        case CHANGE_TYPE.MODIFIED:
            return l("%Modified");
        case CHANGE_TYPE.RENAMED:
            return l("%Renamed");
        default:
            return l("%InvalidChange");
    }
}

function InsertIntoMonitorTable(result) {
    var tmp = $('<tr/>');
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: result.Path
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: result.OldPath
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: result.Name
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: result.OldName
    }));
    $('#FileMonitorResultsTableBody').append(tmp);
}

function ExportToExcel() {
    var data = {
        'BaseId': $('#SelectedBaseRunId').val(),
        'CompareId': $('#SelectedCompareRunId').val(),
        'ResultType': $('input[name=ResultType]:checked').val(),
        'ExportAll': ($('input[name=ExportQuantity]:checked').val() == 1),
        'OutputPath': ($('#DirectoryPath').val() == "") ? $('#DirectoryPath').attr('placeholder') : $('#DirectoryPath').val()
    };
    $.getJSON('WriteScanJson', data, function (results) {
        SetStatus("Results Written");
    });
}

function ExportMonitorResults() {
    var data = {
        'RunId': $('#SelectedMonitorRunId').val(),
        'ResultType': $('input[name=MonitorResultType]:checked').val(),
        'OutputPath': ($('#DirectoryPathMonitor').val() == "") ? $('#DirectoryPathMonitor').attr('placeholder') : $('#DirectoryPathMonitor').val()
    };
    $.getJSON('WriteMonitorJson', data, function (results) {
        SetMonitorStatus("Results written");
    });
}

function InsertIntoTable(result) {
    switch (parseInt(result.ResultType)) {
        case RESULT_TYPE.FILE:
            InsertIntoFileTable(result);
            break;
        case RESULT_TYPE.PORT:
            InsertIntoPortTable(result);
            break;
        case RESULT_TYPE.REGISTRY:
            InsertIntoRegistryTable(result);
            break;
        case RESULT_TYPE.CERTIFICATE:
            InsertIntoCertificateTable(result);
            break;
        case RESULT_TYPE.SERVICE:
            InsertIntoServiceTable(result);
            break;
        case RESULT_TYPE.USER:
            InsertIntoUserTable(result);
            break;
        case RESULT_TYPE.GROUP:
            InsertIntoGroupTable(result);
            break;
        case RESULT_TYPE.FIREWALL:
            InsertIntoFirewallTable(result);
            break;
        case RESULT_TYPE.COM:
            InsertIntoComTable(result);
    }
}

function FlagToStyle(flag) {
    switch (flag) {
        case ANALYSIS_RESULT_TYPE.WARNING:
            return "table-warning";
        case ANALYSIS_RESULT_TYPE.ERROR:
            return "table-danger";
        case ANALYSIS_RESULT_TYPE.FATAL:
            return "table-danger";
        case ANALYSIS_RESULT_TYPE.INFORMATION:
            return "table-info";
        default:
            return "";
    }
}

function FlagToString(flag) {
    switch (flag) {
        case ANALYSIS_RESULT_TYPE.VERBOSE:
            return "Verbose";
        case ANALYSIS_RESULT_TYPE.DEBUG:
            return "Debug";
        case ANALYSIS_RESULT_TYPE.INFORMATION:
            return "Info";
        case ANALYSIS_RESULT_TYPE.WARNING:
            return "Warning";
        case ANALYSIS_RESULT_TYPE.ERROR:
            return "Error";
        case ANALYSIS_RESULT_TYPE.FATAL:
            return "Fatal";

    }
}

function GenerateExpandedResultsCard(result) {
    var card = $('<div/>', {
        class: 'card card-body'
    });
    var header = $('<div/>', {
        class: 'row'
    }).append($('<div/>', {
        class: 'col', html: l('%Property')
    })).append($('<div/>', {
        class: 'col', html: result.BaseRunId
    })).append($('<div/>', {
        class: 'col', html: result.CompareRunId
    }))
    card.append(header);

    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        var protoObj = result.Compare;
    }
    else {
        var protoObj = result.Base;
    }
    for (var prop in protoObj) {
        if (protoObj.hasOwnProperty(prop)) {
            var before, after;
            var row = $('<div/>', {
                class: 'row bordered'
            });

            var property = $('<div/>', { class: 'col-2', html: prop });

            if (result.ChangeType == CHANGE_TYPE.DELETED) {
                before = $('<div/>', { class: 'col-5', html: result.Base[prop] });
                after = $('<div/>', { class: 'col-5' });
            }
            else if (result.ChangeType == CHANGE_TYPE.CREATED) {
                before = $('<div/>', { class: 'col-5' });
                after = $('<div/>', { class: 'col-5', html: result.Compare[prop] });
            }
            else if (result.ChangeType == CHANGE_TYPE.MODIFIED) {
                before = $('<div/>', { class: 'col-5', html: result.Base[prop] });
                after = $('<div/>', { class: 'col-5', html: result.Compare[prop] });
            }
            row.append(property);
            row.append(before);
            row.append(after);

            card.append(row);
        }
    }
    return card;
}

function InsertIntoFileTable(result) {
    var appendObj;
    if (result.ChangeType != CHANGE_TYPE.CREATED) {
        appendObj = result.Base;
    }
    else {
        appendObj = result.Compare;
    }
    var uid = uuidv4();
    var tmp = $('<tr/>', {
        id: uid,
        class: 'resultTableRow Info ' + FlagToStyle(result.Analysis),
    });
    var arrowTD = $('<td/>', {
        scope: 'col',
    });
    var caretContainer = ($('<div/>'));
    var caret = $('<i/>', {
        class: "fas fa-caret-right",
        id: uid + '_expansion_arrow'
    });
    caretContainer.append(caret);
    arrowTD.append(caretContainer);
    tmp.append(arrowTD);
    tmp.append($('<td/>', {
        scope: "col",
        html: FlagToString(result.Analysis)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Path
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Size
    }));
    $('#FileResultsTableBody').append(tmp);
    tmp = $('<tr/>');
    var tmp2 = $('<td/>', {
        colspan: 5,
        class: 'resultTableExpanded',
        id: uid + '_expanded'
    }).append(GenerateExpandedResultsCard(result));
    tmp.append(tmp2);
    $('#FileResultsTableBody').append(tmp);
}

function InsertIntoPortTable(result) {
    var uid = uuidv4();
    var tmp = $('<tr/>', {
        id: uid,
        class: 'resultTableRow Info ' + FlagToStyle(result.Analysis)
    });
    var arrowTD = $('<td/>', {
        scope: 'col',
    });
    var caretContainer = ($('<div/>'));
    var caret = $('<i/>', {
        class: "fas fa-caret-right",
        id: uid + '_expansion_arrow'
    });
    caretContainer.append(caret);
    arrowTD.append(caretContainer);

    tmp.append(arrowTD);
    tmp.append($('<td/>', {
        scope: "col",
        html: FlagToString(result.Analysis)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));

    var appendObj;
    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        appendObj = result.Compare;
    }
    else {
        appendObj = result.Base;
    }

    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.port
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.type
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.address
    }));
    $('#PortResultsTableBody').append(tmp);

    tmp = $('<tr/>');
    var tmp2 = $('<td/>', {
        colspan: 5,
        class: 'resultTableExpanded',
        id: uid + '_expanded'
    }).append(GenerateExpandedResultsCard(result));
    tmp.append(tmp2);
    $('#PortResultsTableBody').append(tmp);

}

function InsertIntoRegistryTable(result) {
    var appendObj;
    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        appendObj = result.Compare;
    }
    else {
        appendObj = result.Base;
    }
    var uid = uuidv4();
    var tmp = $('<tr/>', {
        id: uid,
        class: 'resultTableRow Info ' + FlagToStyle(result.Analysis),
    });
    var arrowTD = $('<td/>', {
        scope: 'col',
    });
    var caretContainer = ($('<div/>'));
    var caret = $('<i/>', {
        class: "fas fa-caret-right",
        id: uid + '_expansion_arrow'
    });
    caretContainer.append(caret);
    arrowTD.append(caretContainer);
    tmp.append(arrowTD);
    tmp.append($('<td/>', {
        scope: "col",
        html: FlagToString(result.Analysis)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Key
    }));
    $('#RegistryResultsTableBody').append(tmp);
    tmp = $('<tr/>');

    var tmp2 = $('<td/>', {
        colspan: 5,
        class: 'resultTableExpanded',
        id: uid + '_expanded'
    }).append(GenerateExpandedResultsCard(result));

    tmp.append(tmp2);
    $('#RegistryResultsTableBody').append(tmp);
}

function InsertIntoCertificateTable(result) {
    var appendObj;
    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        appendObj = result.Compare;
    }
    else {
        appendObj = result.Base;
    }
    var uid = uuidv4();
    var tmp = $('<tr/>', {
        id: uid,
        class: 'resultTableRow Info ' + FlagToStyle(result.Analysis),
    });
    var arrowTD = $('<td/>', {
        scope: 'col',
    });
    var caretContainer = ($('<div/>'));
    var caret = $('<i/>', {
        class: "fas fa-caret-right",
        id: uid + '_expansion_arrow'
    });
    caretContainer.append(caret);
    arrowTD.append(caretContainer);
    tmp.append(arrowTD);
    tmp.append($('<td/>', {
        scope: "col",
        html: FlagToString(result.Analysis)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.StoreLocation
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.StoreName
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Subject
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.CertificateHashString
    }));
    $('#CertificateResultsTableBody').append(tmp);

    tmp = $('<tr/>');
    var tmp2 = $('<td/>', {
        colspan: 5,
        class: 'resultTableExpanded',
        id: uid + '_expanded'
    }).append(GenerateExpandedResultsCard(result));
    tmp.append(tmp2);
    $('#CertificateResultsTableBody').append(tmp);
}


function InsertIntoServiceTable(result) {
    var appendObj;
    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        appendObj = result.Compare;
    }
    else {
        appendObj = result.Base;
    }
    var uid = uuidv4();
    var tmp = $('<tr/>', {
        id: uid,
        class: 'resultTableRow Info ' + FlagToStyle(result.Analysis),
    });
    var arrowTD = $('<td/>', {
        scope: 'col',
    });
    var caretContainer = ($('<div/>'));
    var caret = $('<i/>', {
        class: "fas fa-caret-right",
        id: uid + '_expansion_arrow'
    });
    caretContainer.append(caret);
    arrowTD.append(caretContainer);
    tmp.append(arrowTD);
    tmp.append($('<td/>', {
        scope: "col",
        html: FlagToString(result.Analysis)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.ServiceName
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.StartType
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.DisplayName
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.CurrentState
    }));
    $('#ServiceResultsTableBody').append(tmp);
    tmp = $('<tr/>');
    var tmp2 = $('<td/>', {
        colspan: 5,
        class: 'resultTableExpanded',
        id: uid + '_expanded'
    }).append(GenerateExpandedResultsCard(result));
    tmp.append(tmp2);
    $('#ServiceResultsTableBody').append(tmp);
}

function InsertIntoUserTable(result) {
    var appendObj;
    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        appendObj = result.Compare;
    }
    else {
        appendObj = result.Base;
    }

    var uid = uuidv4();
    var tmp = $('<tr/>', {
        id: uid,
        class: 'resultTableRow Info ' + FlagToStyle(result.Analysis),
    });
    var arrowTD = $('<td/>', {
        scope: 'col',
    });
    var caretContainer = ($('<div/>'));
    var caret = $('<i/>', {
        class: "fas fa-caret-right",
        id: uid + '_expansion_arrow'
    });
    caretContainer.append(caret);
    arrowTD.append(caretContainer);
    tmp.append(arrowTD);
    tmp.append($('<td/>', {
        scope: "col",
        html: FlagToString(result.Analysis)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.AccountType
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Name
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Description
    }));
    $('#UserResultsTableBody').append(tmp);

    tmp = $('<tr/>');
    var tmp2 = $('<td/>', {
        colspan: 5,
        class: 'resultTableExpanded',
        id: uid + '_expanded'
    }).append(GenerateExpandedResultsCard(result));
    tmp.append(tmp2);
    $('#UserResultsTableBody').append(tmp);
}

function InsertIntoGroupTable(result) {
    var appendObj;
    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        appendObj = result.Compare;
    }
    else {
        appendObj = result.Base;
    }

    var uid = uuidv4();
    var tmp = $('<tr/>', {
        id: uid,
        class: 'resultTableRow Info ' + FlagToStyle(result.Analysis),
    });
    var arrowTD = $('<td/>', {
        scope: 'col',
    });
    var caretContainer = ($('<div/>'));
    var caret = $('<i/>', {
        class: "fas fa-caret-right",
        id: uid + '_expansion_arrow'
    });
    caretContainer.append(caret);
    arrowTD.append(caretContainer);
    tmp.append(arrowTD);
    tmp.append($('<td/>', {
        scope: "col",
        html: FlagToString(result.Analysis)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Domain
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Name
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Description
    }));
    $('#UserResultsTableBody').append(tmp);

    tmp = $('<tr/>');
    var tmp2 = $('<td/>', {
        colspan: 5,
        class: 'resultTableExpanded',
        id: uid + '_expanded'
    }).append(GenerateExpandedResultsCard(result));
    tmp.append(tmp2);
    $('#GroupResultsTableBody').append(tmp);
}

function InsertIntoFirewallTable(result) {
    var appendObj;
    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        appendObj = result.Compare;
    }
    else {
        appendObj = result.Base;
    }

    var uid = uuidv4();
    var tmp = $('<tr/>', {
        id: uid,
        class: 'resultTableRow Info ' + FlagToStyle(result.Analysis),
    });
    var arrowTD = $('<td/>', {
        scope: 'col',
    });
    var caretContainer = ($('<div/>'));
    var caret = $('<i/>', {
        class: "fas fa-caret-right",
        id: uid + '_expansion_arrow'
    });
    caretContainer.append(caret);
    arrowTD.append(caretContainer);
    tmp.append(arrowTD);
    tmp.append($('<td/>', {
        scope: "col",
        html: FlagToString(result.Analysis)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.FriendlyName
    }));
    $('#FirewallResultsTableBody').append(tmp);

    tmp = $('<tr/>');
    var tmp2 = $('<td/>', {
        colspan: 5,
        class: 'resultTableExpanded',
        id: uid + '_expanded'
    }).append(GenerateExpandedResultsCard(result));
    tmp.append(tmp2);
    $('#FirewallResultsTableBody').append(tmp);
}

function InsertIntoComTable(result) {
    var appendObj;
    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        appendObj = result.Compare;
    }
    else {
        appendObj = result.Base;
    }

    var uid = uuidv4();
    var tmp = $('<tr/>', {
        id: uid,
        class: 'resultTableRow Info ' + FlagToStyle(result.Analysis),
    });
    var arrowTD = $('<td/>', {
        scope: 'col',
    });
    var caretContainer = ($('<div/>'));
    var caret = $('<i/>', {
        class: "fas fa-caret-right",
        id: uid + '_expansion_arrow'
    });
    caretContainer.append(caret);
    arrowTD.append(caretContainer);
    tmp.append(arrowTD);
    tmp.append($('<td/>', {
        scope: "col",
        html: FlagToString(result.Analysis)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: ChangeTypeToString(result.ChangeType)
    }));
    tmp.append($('<td/>', {
        scope: "col",
        html: appendObj.Key.Key
    }));
    if (appendObj.hasOwnProperty("x86_BinaryName")) {
        tmp.append($('<td/>', {
            scope: "col",
            html: appendObj.x86_BinaryName
        }));
    }
    else if (appendObj.hasOwnProperty("x64_BinaryName")) {
        tmp.append($('<td/>', {
            scope: "col",
            html: appendObj.x64_BinaryName
        }));
    }
    else {
        tmp.append($('<td/>', {
            scope: "col",
            html: "Check details"
        }));
    }
    $('#ComResultsTableBody').append(tmp);

    tmp = $('<tr/>');
    var tmp2 = $('<td/>', {
        colspan: 5,
        class: 'resultTableExpanded',
        id: uid + '_expanded'
    }).append(GenerateExpandedResultsCard(result));
    tmp.append(tmp2);
    $('#ComResultsTableBody').append(tmp);
}


function GenerateExpandedResultsCard(result) {
    var card = $('<div/>', {
        class: 'card card-body'
    });
    var header = $('<div/>', {
        class: 'row'
    }).append($('<div/>', {
        class: 'col', html: l('%Property')
    })).append($('<div/>', {
        class: 'col', html: result.BaseRunId
    })).append($('<div/>', {
        class: 'col', html: result.CompareRunId
    }))
    card.append(header);

    if (result.ChangeType == CHANGE_TYPE.MODIFIED) {
        for (var diff in result.Diffs) {
            var row = $('<div/>', {
                class: 'row bordered diff'
            });
            var field = $('<div/>', { class: 'col-2', html: result.Diffs[diff].Field });
            var before = $('<div/>', { class: 'col-5', html: result.Diffs[diff].Before });
            var after = $('<div/>', { class: 'col-5', html: result.Diffs[diff].After });
            row.append(field);
            row.append(before);
            row.append(after);

            card.append(row);
        }
    }
    if (result.ChangeType == CHANGE_TYPE.CREATED) {
        var protoObj = result.Compare;
    }
    else {
        var protoObj = result.Base;
    }
    for (var prop in protoObj) {
        if (protoObj.hasOwnProperty(prop)) {
            var before, after;
            var row = $('<div/>', {
                class: 'row bordered'
            });

            var property = $('<div/>', { class: 'col-2', html: prop });

            if (result.ChangeType == CHANGE_TYPE.DELETED) {
                before = $('<div/>', { class: 'col-5', html: result.Base[prop] });
                after = $('<div/>', { class: 'col-5' });
            }
            else if (result.ChangeType == CHANGE_TYPE.CREATED) {
                before = $('<div/>', { class: 'col-5' });
                after = $('<div/>', { class: 'col-5', html: result.Compare[prop] });
            }
            else if (result.ChangeType == CHANGE_TYPE.MODIFIED) {
                before = $('<div/>', { class: 'col-5', html: result.Base[prop] });
                after = $('<div/>', { class: 'col-5', html: result.Compare[prop] });
            }
            row.append(property);
            row.append(before);
            row.append(after);

            card.append(row);
        }
    }
    return card;
}