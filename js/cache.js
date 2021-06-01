webpackJsonp([2],{

/***/ 29:
/***/ (function(module, exports) {

var port = chrome.extension.connect({
	name: "cache_comm"
});
port.postMessage("cache");
function ActionName(value) {
	if (value === 0)
		return "ALLOW"; 
	let ret = "";
	if (value & 0x1)
		ret += "CANCEL ";
	if (value & 0x2)
		ret += "BLOCK ";
	if (value & 0x4)
		ret += "REDIRECT ";
	if (value & 0x8)
		ret += "ADDARGS ";
	if (value & 0x10)
		ret += "ADDHEADERS ";
	if (ret === "")
		return value;
	return ret;
}
port.onMessage.addListener(function(cache) {
	let table = document.getElementById('cache');
	let index = 1;
	for (let key in cache) {
		let row = table.insertRow(index++);
		row.insertCell(0).innerHTML = cache[key]['value']['group'];
		row.insertCell(1).innerHTML = key;
		row.insertCell(2).innerHTML = cache[key]['value']['cache'];
		row.insertCell(3).innerHTML = ActionName(cache[key]['value']['action']);
		row.insertCell(4).innerHTML = cache[key]['value']['category'];
		let headersCell = row.insertCell(5);
		if (cache[key]['value']['action'] & 0x10) {
			let headers = cache[key]['value']['headers'];
			for (let i =0; i < headers.length; i++) {
				if (i > 0) headersCell.innerHTML += ", ";
				headersCell.innerHTML += headers[i]['name'] + ': ' + headers[i]['value'];
			}
		}
		let argsCell = row.insertCell(6);
		if (cache[key]['value']['action'] & 0x8) {
			let args = cache[key]['value']['args'];
			for (let i =0; i < args.length; i++) {
				if (i > 0) argsCell.innerHTML += ", ";
				argsCell.innerHTML += args[i];
			}
		}
		row.insertCell(7).innerHTML = cache[key]['timeout'];
	}
});



/***/ })

},[29]);
