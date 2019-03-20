const HandleBars = require('handlebars')
const helpers = require('handlebars-helpers')
const math = helpers.math()
const fs = require('fs')
const sysPath = require('path')

const matches = (text, pattern) => ({
    [Symbol.iterator]: function * () {
      const clone = new RegExp(pattern.source, pattern.flags);
      let match = null;
      do {
        match = clone.exec(text);
        if (match) {
          yield match;
        }
      } while (match);
    }
});

function parseVerifierKey(verifierKeyPath) {

    let output = {IC:[]}
    let verifierKey = fs.readFileSync(verifierKeyPath, 'utf-8')
    // trim all whitespace
    verifierKey = verifierKey.replace(/ /g, '')
    // strip IC initialization
    verifierKey = verifierKey.replace(/vk.IC.len\(\)[^\n]*/g, '')
    // strip vk variable prefix
    verifierKey = verifierKey.replace(/vk./g, '')
    // begin variable assignment
    for (const match of matches(verifierKey, /([a-zA-Z0-9]+)\[?([0-9])*\]?=([^\n]*)/g)) {
        if (match[2]) {
            output[match[1]][match[2]] = match[3]
        } else {
            output[match[1]] = match[3]
        }
    }
    return output
}

function generateTemplate(verifierKeyPath, templateOutputPath) {
  const parsedKey = parseVerifierKey(verifierKeyPath)
  const templatePath = sysPath.join(sysPath.resolve(__dirname, '..', '..', 'contracts', 'lib'), 'VerifierTemplate.handlebars')
  const templateSource = fs.readFileSync(templatePath, 'utf-8')
  const templateCompiled = HandleBars.compile(templateSource)
  const output = templateCompiled(parsedKey)
  fs.writeFileSync(templateOutputPath, output, 'utf-8')  
}

module.exports = generateTemplate