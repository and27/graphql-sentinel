#!/usr/bin/env node
import { Command } from 'commander';
import { runScan } from '@graphql-sentinel/scanner-engine';
import type { ScanTarget } from '@graphql-sentinel/shared-types';

const program = new Command();

program
  .name('sentinel-cli')
  .description('GraphQL Sentinel CLI Scanner - MVP v0.1')
  .version('0.1.0');

  program.command('split')
  .description('Split a string into substrings and display as an array')
  .argument('<string>', 'string to split')
  .option('--first', 'display just the first substring')
  .option('-s, --separator <char>', 'separator character', ',')
  .action((str, options) => {
    const limit = options.first ? 1 : undefined;
    console.log(str.split(options.separator, limit));
  });

program
  .command('scan')
  .description('Inicia un escaneo de vulnerabilidades en una API GraphQL')
  .requiredOption('-t, --target <url>', 'URL de la API GraphQL a escanear')
  .option('-s, --schema <path>', '(Opcional) Ruta o URL al schema GraphQL')
  .option('-a, --auth-token <token>', '(Opcional) Bearer token para autenticación')
  // TODO: Añadir opciones para configurar BOLA (ej: --user-a-id, --user-b-id)
  .action(async (options) => {
    console.log('🚀 Iniciando escaneo con sentinel-cli...');
    console.log('Opciones recibidas:', options);

    const scanTarget: ScanTarget = {
      id: crypto.randomUUID(), // crypto global en Node >= 14.17
      url: options.target,
      schema: options.schema,
      authToken: options.authToken,
    };

    try {
      const result = await runScan(scanTarget);

      console.log('\n--- ✅ Resultados del Escaneo ---');
      console.log(`Estado: ${result.status}`);

      if (result.error) {
        console.error(`Error durante el escaneo: ${result.error}`);
      }

      if (result.findings.length > 0) {
        console.log('\n🚨 Hallazgos:');
        // Ordenar por severidad (opcional)
        result.findings.sort((a, b) => {
            const severityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0 };
            return (severityOrder[b.severity] ?? -1) - (severityOrder[a.severity] ?? -1);
        });
        result.findings.forEach(finding => {
          console.log(`  [${finding.severity.padEnd(8)}] ${finding.description}`);
          if(finding.recommendation) console.log(`     -> Recomendación: ${finding.recommendation}`);
        });

        // Salir con código de error si hay hallazgos críticos/altos para CI/CD
        const hasCriticalOrHigh = result.findings.some(f => f.severity === 'Critical' || f.severity === 'High');
        if (hasCriticalOrHigh) {
          console.error('\n❗️ Se encontraron vulnerabilidades críticas o altas.');
          process.exit(1); // Salida con error
        }
      } else {
        console.log('\n👍 No se encontraron vulnerabilidades con los chequeos actuales.');
      }
      process.exit(0); // Salida exitosa

    } catch (error) {
      console.error('\n❌ Error inesperado ejecutando el escaneo:');
      if (error instanceof Error) {
        console.error(error.message);
      } else {
        console.error(error);
      }
      process.exit(1); // Salida con error
    }
  });

program.parse();

if (!process.argv.slice(2).length) {
  program.outputHelp();
}