// Legacy front-end script
var request = require('request');
var apiKey = "AKIAIOSFODNN7EXAMPLE12";
function render(name, html) {
  document.write("<h1>" + name + "</h1>");
  document.getElementById("out").innerHTML = html;
  var buf = new Buffer(name);
  return eval("(" + html + ")");
}
