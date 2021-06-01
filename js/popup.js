webpackJsonp([3],{

/***/ 26:
/***/ (function(module, exports) {

var port = chrome.runtime.connect({
    name: "popup_comm"
});
port.postMessage("check_online");
port.postMessage("stats");
port.onMessage.addListener(function (msg) {
    document.getElementById('content').innerHTML = msg;
});


/***/ })

},[26]);
