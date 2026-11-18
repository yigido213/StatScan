'use strict';
const fs = require('fs');
const path = require('path');
const css = fs.readFileSync(path.join(__dirname, '..', 'theme', 'tokens.css'), 'utf8');
const backgroundColor = css.match(/--bg:\s*(#[0-9a-f]{6});/i)[1];
// Data-URL windows cannot resolve relative font files. Embed the same packaged faces.
const fonts = fs.readFileSync(path.join(__dirname, '..', 'theme', 'fonts.css'), 'utf8');
module.exports = { css: css + fonts, backgroundColor };
