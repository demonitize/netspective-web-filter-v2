webpackJsonp([5],{

/***/ 28:
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const moment = __webpack_require__(3);
var port = chrome.runtime.connect({
    name: "logs_comm"
});
port.postMessage("logs");
port.onMessage.addListener(function (logs) {
    let table = document.getElementById('logs');
    for (let i = 0; i < logs.length; i++) {
        let row = table.insertRow(0);
        let dateTimeCell = row.insertCell(0);
        let msgCell = row.insertCell(1);
        dateTimeCell.setAttribute("style", "width: 160px; min-width: 160px; vertical-align: top; word-wrap: break-word");
        dateTimeCell.innerHTML = moment(logs[i].ts).format('YYYY-MM-DD HH:mm:ss');
        msgCell.innerHTML = ' ' + logs[i].level + ' ' + logs[i].msg;
        msgCell.setAttribute("style", "width: 800px; min-width: 800px; max-width: 800px; word-wrap: break-word;");
    }
});


/***/ })

},[28]);
