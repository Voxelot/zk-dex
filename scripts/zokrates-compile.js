const exec = require('child_process').execSync
const klaw = require('klaw')
const sysPath = require('path')
const mkdirp = require('mkdirp-promise')
const verifyKeyCompiler = require('./lib/compile-verify-template.js')

async function generateVerifier(path) {
    const circuitName = sysPath.basename(path)
    const verifierDir = sysPath.resolve(sysPath.dirname(path), '..', 'contracts', 'verifiers')
    const verifierName = circuitName.slice(0, 1).toUpperCase().concat(circuitName.slice(1, circuitName.indexOf('.code'))) + 'Verifier'
    const outputPath = sysPath.join(verifierDir, verifierName + '.sol')
    console.log(`compiling ${path} verifier...`)
    exec(`docker run -t -d --name zkcompile --rm zokrates/zokrates`)
    console.log(`docker cp ${path} zkcompile:/home/zokrates`)
    exec(`docker cp ${path} zkcompile:/home/zokrates`)
    exec(`docker exec --workdir=/home/zokrates zkcompile ./zokrates compile -i ${circuitName}`)
    exec(`docker exec --workdir=/home/zokrates zkcompile ./zokrates setup`)
    exec(`docker exec --workdir=/home/zokrates zkcompile ./zokrates export-verifier`)
    exec(`docker exec --workdir=/home/zokrates zkcompile ls`)
    const buildDir = sysPath.resolve(__dirname, '..', 'build', verifierName)
    await mkdirp(buildDir)
    exec(`docker cp zkcompile:/home/zokrates/proving.key ${sysPath.join(buildDir, 'proving.key')}`)
    const verificationKeyPath = sysPath.join(buildDir, 'verification.key')
    exec(`docker cp zkcompile:/home/zokrates/verification.key ${verificationKeyPath}`)
    exec(`docker kill zkcompile`)
    verifyKeyCompiler(verificationKeyPath, outputPath)
    console.log(`compiled verifier contract to ${outputPath}`)
}

(async () => {
    // cleanup previous containers
    try {
        exec(`docker kill zkcompile`, {stderr: 'ignore'})
    } catch (e) {}

    console.log(`Compiling circuits in ${sysPath.resolve(__dirname, '..', 'circuits')}`)
    const dirStream = klaw(sysPath.resolve(__dirname, '..', 'circuits'))
    for await (const item of dirStream) {
        if (item.path.indexOf('.code') != -1) {
            await generateVerifier(item.path)
        }
        
    }
    process.exit(0)
})()
