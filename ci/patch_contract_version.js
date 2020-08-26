#!/usr/bin/env node

const path = require('path')
const fs = require('fs')

async function main() {
  let packageJson = require(path.join(__dirname, '../package.json'))
  if (process.env.PATCH_RAINBOW_BRIDGE_SOL) {
    packageJson.dependencies[
      'rainbow-bridge-sol'
    ] = `near/rainbow-bridge-sol#${process.env.PATCH_RAINBOW_BRIDGE_SOL}`
  }
  if (process.env.PATCH_RAINBOW_BRIDGE_RS) {
    packageJson.dependencies[
      'rainbow-bridge-rs'
    ] = `near/rainbow-bridge-rs#${process.env.PATCH_RAINBOW_BRIDGE_RS}`
  }
  console.log('Contract versions:')
  console.log(
    `rainbow-bridge-sol: ${packageJson.dependencies['rainbow-bridge-sol']}`
  )
  console.log(
    `rainbow-bridge-rs: ${packageJson.dependencies['rainbow-bridge-rs']}`
  )
  if (
    !process.env.PATCH_RAINBOW_BRIDGE_SOL &&
    !process.env.PATCH_RAINBOW_BRIDGE_RS
  ) {
    process.exit()
  }

  fs.writeFileSync(
    path.join(__dirname, '../package.json'),
    JSON.stringify(packageJson)
  )
}

main()