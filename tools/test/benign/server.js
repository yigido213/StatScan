const http = require('http');
const fs = require('fs');
http.createServer((req, res) => { res.writeHead(200, {'Content-Type':'text/plain'}); res.end('merhaba'); }).listen(3000);
console.log('http://localhost:3000');
