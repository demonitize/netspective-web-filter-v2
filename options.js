webpackJsonp([4],{

/***/ 27:
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
var defaultLogLevel = 'INFO';
function LoadOptions() {
    chrome.storage.managed.get(['Appliances'], function (mresult) {
        let managed = { Appliances: mresult.Appliances };
        chrome.storage.local.get(['debug', 'stats_enabled', 'Appliances', 'md5'], function (lresult) {
            let local = { Appliances: lresult.Appliances, debug: lresult.debug, stats_enabled: lresult.stats_enabled, configuration: { md5: lresult.md5 } };
            if ((typeof (local.debug) === "undefined") ||
                (local.debug !== 'INFO' &&
                    local.debug !== 'DEBUG' &&
                    local.debug !== 'TRACE')) {
                local.debug = defaultLogLevel;
            }
            let select = document.getElementById('logLevel');
            for (let i = 0; i < select.children.length; i++) {
                let child = select.children[i];
                if (child.value === local.debug) {
                    child.selected = 'true';
                    break;
                }
            }
            if ((typeof (local.stats_enabled) !== "undefined") &&
                ((local.stats_enabled === true) ||
                    (local.stats_enabled === 'true'))) {
                local.stats_enabled = true;
            }
            else {
                local.stats_enabled = false;
            }
            let checkbox = document.getElementById('stats_enabled');
            checkbox.checked = local.stats_enabled;
            let managedlist = document.getElementById('managed');
            if (typeof (managed.Appliances) !== "undefined") {
                for (let i = 0; i < managed.Appliances.length; i++) {
                    let entry = document.createElement('li');
                    entry.appendChild(document.createTextNode(managed.Appliances[i]));
                    managedlist.appendChild(entry);
                }
            }
            if (typeof (local.Appliances) !== "undefined") {
                for (let i = 0; i < local.Appliances.length; i++) {
                    _AddAppliance(local.Appliances[i]);
                }
            }
            if (typeof (local.configuration.md5 !== "undefined")) {
                document.getElementById('configuration').value = local.configuration.md5;
            }
        });
    });
}
function _AddAppliance(address) {
    if (document.getElementById(address)) {
        console.log('already exists');
        return;
    }
    let list = document.getElementById('appliances');
    let entry = document.createElement('li');
    entry.className = "address_entry";
    entry.id = address;
    entry.appendChild(document.createTextNode(address));
    list.appendChild(entry);
}
function AddAppliance() {
    let address_input = document.getElementById('address_input');
    _AddAppliance(address_input.value);
    address_input.value = "";
}
function RemoveAppliance() {
    let address_input = document.getElementById('address_input');
    let entry = document.getElementById(address_input.value);
    if (entry) {
        entry.outerHTML = "";
    }
    address_input.value = "";
}
function ClearAppliances() {
    let list = document.getElementById('appliances');
    list.innerHTML = "";
}
function SaveOptions() {
    let Appliances = [];
    let addresses = document.getElementsByClassName("address_entry");
    for (let i = 0; i < addresses.length; i++)
        Appliances.push(addresses[i].innerHTML);
    chrome.storage.local.set({ 'Appliances': Appliances });
    let select = document.getElementById('logLevel');
    let logLevel = select.children[select.selectedIndex].value;
    if (logLevel == undefined ||
        (logLevel != 'INFO' &&
            logLevel != 'DEBUG' &&
            logLevel != 'TRACE')) {
        chrome.storage.local.remove('debug');
    }
    else {
        chrome.storage.local.set({ 'debug': logLevel });
    }
    let checkbox = document.getElementById('stats_enabled');
    if (checkbox.checked) {
        chrome.storage.local.set({ 'stats_enabled': true });
    }
    else {
        chrome.storage.local.remove('stats_enabled');
    }
    let usernameElement = document.getElementById("user_id");
    let useridElement = document.getElementById("username");

    chrome.storage.local.set({'netspectiveUsername': usernameElement.value, 'netspectiveUserID': useridElement.value});
}
function ResetOptions() {
    chrome.storage.local.remove('debug');
    location.reload();
}
LoadOptions();
document.getElementById('add').addEventListener('click', AddAppliance);
document.getElementById('remove').addEventListener('click', RemoveAppliance);
document.getElementById('clear').addEventListener('click', ClearAppliances);
document.getElementById('save').addEventListener('click', SaveOptions);
document.getElementById('reset').addEventListener('click', ResetOptions);


/***/ })

},[27]);