// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
"use strict"
$('#CollectLink').addClass('active');

EnableCollectionFields();
$("#StartCollectionButton").click(StartCollection);
$("#StopMonitoringButton").click(StopMonitoring);
$("#StopMonitoringButton").hide();

$("#ClearResults").click(function(){
    clearRows();
});

$("#DirectorySelector").change(function () {
    $("#DirectoryPath").val($('#DirectorySelector')[0].files[0].path);
});

var group = $('input[type=radio][name=ScanType]');
group.change(function () {
    $('.scan').toggle(group.filter(':checked').val() === 'Static');
    $('.monitor').toggle(group.filter(':checked').val() === 'Live');
}).change();

GetCollectors();

function StopMonitoring()
{
    $("#StartCollectionButton").show();
    $("#StopMonitoringButton").hide();
    EnableCollectionFields();
    $.getJSON("StopMonitoring");
}

function StartCollection()
{
    DisableCollectionFields();

    if (group.filter(':checked').val() === "Live")
    {
        $("#StartCollectionButton").hide();
        $("#StopMonitoringButton").show();

        if ($("#directory").val() == "")
        {
            $('#ScanStatus').empty();
            $('#ScanStatus').append($('<div/>', { html: "ERROR: Must specify a directory to watch.", class: 'scan' }));
            EnableCollectionFields();
        }
        else
        {

            var monitor = { 
                RunId: ($('#RunId').val() == "") ? $('#RunId').attr('placeholder') : $('#RunId').val(),
                Directory: ($('#DirectoryPath').val() == "") ? $('#DirectoryPath').attr('placeholder'): $('#DirectoryPath').val(),
                Extension:$('#extension').val()
            }

            $.getJSON("StartMonitoring", monitor, function (result) {
                $('#ScanStatus').empty();
                if (result === ERRORS.UNIQUE_ID) {
                    $('#ScanStatus').append($('<div/>', { html: "Must supply unique run id." }));
                    EnableCollectionFields();
                }
                else {
                    $('#ScanStatus').append($('<div/>', { html: "Run started." }));
                    setTimeout(GetMonitorStatus, 250)
                }
            });
        }
    }
    else if (group.filter(':checked').val() === "Static")
    {
        if ($("#enableFileCollector").is(":checked") == false && 
            $("#enablePortCollector").is(":checked") == false && 
            $("#enableServiceCollector").is(":checked") == false && 
            $("#enableUserCollector").is(":checked") == false && 
            $("#enableRegistryCollector").is(':checked') == false && 
            $('#enableCertificateCollector').is(":checked") == false)
        {
            $('#ScanStatus').empty();
            $('#ScanStatus').append($('<div/>', { html: "ERROR: Must select at least one collector.", class: 'scan' }));
            EnableCollectionFields();
        }
        else
        {

            var collect = { 
                Id: ($('#RunId').val()=="")?$('#RunId').attr('placeholder'):$('#RunId').val(),
                File:$('#enableFileCollector').is(":checked"),
                Port:$('#enablePortCollector').is(":checked"),
                Service:$('#enableServiceCollector').is(":checked"),
                User:$('#enableUserCollector').is(":checked"),
                Registry:$('#enableRegistryCollector').is(":checked"),
                Certificates:$('#enableCertificateCollector').is(":checked"),
            }
            
            $.getJSON("StartCollection", collect, function (result) {
                $('#ScanStatus').empty();
                if (result === ERRORS.UNIQUE_ID) {
                    $('#ScanStatus').append($('<div/>', { html: "Must supply unique run id." }));
                    EnableCollectionFields();
                }
                else {
                    $('#ScanStatus').append($('<div/>', { html: '<i class="fas fa-cog fa-spin"></i>  <i>Collection has started. Please do not close the application or navigate to other pages until collection is complete.</i>' }));
                    setTimeout(GetCollectors, 500)
                }
            });
        }
    }
}

function GetMonitorStatus() {
    $.getJSON('GetMonitorStatus', function (result) {
        var data = JSON.parse(result);
        var keepChecking = false;
        var icon, midword;
        $('#ScanStatus').empty();

        $.each(data, function (key, value) {
            if (value === RUN_STATUS.RUNNING) {
                keepChecking = true;
                icon = '<i class="fas fa-cog fa-spin"></i>  ';
                midword = ' is ';
            }
            else if (value === RUN_STATUS.COMPLETED) {
                icon = '<i class="far fa-check-circle" style="color:green"></i>  ';
                midword = ' has ';
            }
            else if (value === RUN_STATUS.NOT_STARTED) {
                icon = '<i class="fas fa-cog"></i>  ';
                midword = ' has ';
            }
            else if (value === RUN_STATUS.NO_RESULTS) {
                icon = '<i class="far fa-check-circle" style="color:yellow"></i>  ';
                midword = ' has ';
            }
            else {
                icon = '<i class="fas fa-exclamation-triangle"></i>  ';
                midword = ' has ';
            }
            $('#ScanStatus').append($('<div/>', { html: icon + key + midword + runStatusToString(value), class: 'monitor' }));
        });
        if (keepChecking) {
            DisableCollectionFields();
            setTimeout(GetMonitorStatus, 250);
            $('#ScanStatus').append($('<div/>', { html: "<i>Monitoring is running. Please begin installation of your test product.</i>" }));
        }
        else {
            $('#ScanStatus').append($('<div/>', { html: "<i>Monitoring is completed.</i>" }));
            EnableCollectionFields();
        }
    });
}

function GetCollectors() {
    $.getJSON('GetCollectors', function (result) {
        var data = JSON.parse(result);
        var keepChecking = false;
        var anyCollectors = false;
        var icon, midword;
        $('#ScanStatus').empty();

        $.each(data, function (key, value) {
            anyCollectors = true;
            if (value === RUN_STATUS.RUNNING) {
                keepChecking = true;
                icon = '<i class="fas fa-cog fa-spin"></i>  ';
                midword = ' is ';
            }
            else if (value === RUN_STATUS.COMPLETED) {
                icon = '<i class="far fa-check-circle" style="color:green"></i>  ';
                midword = ' has ';
            }
            else if (value === RUN_STATUS.NOT_STARTED) {
                icon = '<i class="fas fa-cog"></i>  ';
                midword = ' has ';
            }
            else if (value === RUN_STATUS.NO_RESULTS) {
                icon = '<i class="far fa-check-circle" style="color:yellow"></i>  ';
                midword = ' has ';
            }
            else {
                icon = '<i class="fas fa-exclamation-triangle"></i>  ';
                midword = ' has ';
            }
            $('#ScanStatus').append($('<div/>', { html: icon + key + midword + runStatusToString(value), class: 'scan' }));
        });
        if (keepChecking) {
            DisableCollectionFields();
            $('#ScanStatus').append($('<div/>', { html: '<i>Collection has started. Please do not close the application or navigate to other pages until collection is complete.</i>' }));
            setTimeout(GetCollectors, 250);
        }
        else {
            if (anyCollectors) {
                $('#ScanStatus').append($('<div/>', { html: "<i>Collection is completed.</i>" }));
            }
            else {
                $('#ScanStatus').append($('<div/>', { html: "<i>Ready to begin collection.</i>" }));
            }
            EnableCollectionFields();
        }
    });
}

function DisableCollectionFields() {
    $("#StartCollectionButton").prop("disabled", true);
    $('#RunId').prop('disabled', true);
    $(".ScanType").prop('disabled', true);
}

function EnableCollectionFields() {
    $("#StartCollectionButton").prop("disabled", false);
    $('#RunId').prop('disabled', false);
    $(".ScanType").prop('disabled', false);
    if ($('#RunId').val() == "") {
        $('#RunId').prop('placeholder', new Date().toLocaleString(undefined, {
            day: '2-digit',
            month: '2-digit',
            year: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }));
    }
}
