import { Command } from 'commander'
import fs from 'fs'
import path from 'path'
import { runScan } from '@graphql-sentinel/scanner-engine'
import type { ScanTarget, UserContext } from '@graphql-sentinel/shared-types'

const program = new Command()

program
  .name('sentinel-cli')
  .description('GraphQL Sentinel CLI Scanner')
  .version('0.2.0')
  .requiredOption(
    '-c, --config <path>',
    'Ruta al archivo de configuración JSON del escaneo'
  )
  .action(async (options) => {
    console.log('🚀 Iniciando escaneo con sentinel-cli...')
    console.log('Opciones recibidas:', options)

    let scanConfig: Partial<ScanTarget> = {}

    try {
      const configPath = path.resolve(options.config)
      console.log(` Cargando configuración desde: ${configPath}`)
      if (!fs.existsSync(configPath)) {
        throw new Error(
          `El archivo de configuración no existe en: ${configPath}`
        )
      }
      const configFileContent = fs.readFileSync(configPath, 'utf-8')
      scanConfig = JSON.parse(configFileContent)
    } catch (error) {
      console.error(
        '\n❌ Error leyendo o parseando el archivo de configuración:'
      )
      if (error instanceof Error) console.error(error.message)
      else console.error(error)
      process.exit(1)
    }

    if (
      !scanConfig.url ||
      !scanConfig.userContexts ||
      !Array.isArray(scanConfig.userContexts) ||
      scanConfig.userContexts.length === 0
    ) {
      console.error(
        '\n❌ Error: El archivo de configuración debe contener al menos "url" y un array "userContexts" no vacío.'
      )
      process.exit(1)
    }

    const scanTarget: ScanTarget = {
      id: crypto.randomUUID(),
      url: scanConfig.url,
      schema: scanConfig.schema,
      userContexts: scanConfig.userContexts as UserContext[],
      bolaConfig: scanConfig.bolaConfig,
    }

    try {
      const result = await runScan(scanTarget)

      console.log('\n--- ✅ Resultados del Escaneo ---')
      console.log(`Estado: ${result.status}`)

      if (result.error) {
        console.error(`Error durante el escaneo: ${result.error}`)
      }

      if (result.findings.length > 0) {
        console.log('\n🚨 Hallazgos:')
        result.findings.sort((a, b) => {
          const severityOrder = {
            Critical: 4,
            High: 3,
            Medium: 2,
            Low: 1,
            Info: 0,
          }
          return (
            (severityOrder[b.severity] ?? -1) -
            (severityOrder[a.severity] ?? -1)
          )
        })
        result.findings.forEach((finding) => {
          console.log(
            `  [${finding.severity.padEnd(8)}] ${finding.description}`
          )
          if (finding.recommendation)
            console.log(`     -> Recomendación: ${finding.recommendation}`)
        })

        const hasCriticalOrHigh = result.findings.some(
          (f) => f.severity === 'Critical' || f.severity === 'High'
        )
        if (hasCriticalOrHigh) {
          console.error(
            '\n❗️ Se encontraron vulnerabilidades críticas o altas.'
          )
          process.exit(1)
        }
      } else {
        console.log(
          '\n👍 No se encontraron vulnerabilidades con los chequeos actuales.'
        )
      }
      process.exit(0)
    } catch (error) {
      console.error('\n❌ Error inesperado ejecutando el escaneo:')
      if (error instanceof Error) console.error(error.message)
      else console.error(error)
      process.exit(1)
    }
  })

program.parse(process.argv)

if (!process.argv.slice(2).length) {
  program.outputHelp()
}
