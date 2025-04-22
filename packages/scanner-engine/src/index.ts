import { GraphQLSchema } from 'graphql'
import type {
  ScanTarget,
  ScanResult,
  VulnerabilityFinding,
  UserContext,
} from '@graphql-sentinel/shared-types'
import { buildHeaders, getErrorMessage, createFinding } from './utils'
import { runBolaChecks } from './bolaTester'
import axios from 'axios'
import { getSchema } from './schemaFetcher'
import { runDosChecks } from './dosScanner'

export async function runScan(target: ScanTarget): Promise<ScanResult> {
  console.log(`[Engine] Iniciando escaneo para: ${target.url}`)
  const startTime = new Date()
  const findings: VulnerabilityFinding[] = []
  let schema: GraphQLSchema | null = null
  let scanStatus: ScanResult['status'] = 'Running'
  let scanError: string | undefined = undefined

  try {
    const initialContext = target.userContexts?.[0] // Usa el primer contexto para pruebas iniciales
    const initialHeaders = buildHeaders(initialContext?.authToken)
    try {
      console.log('[Engine] Verificando conectividad...')
      await axios.post(
        target.url,
        { query: '{ __typename }' },
        { headers: initialHeaders, timeout: 5000 }
      )
      console.log('[Engine] Conectividad OK.')
    } catch (error) {
      throw new Error(
        `No se pudo conectar a ${target.url}. Verifica la URL, la red y el token inicial si aplica. Error: ${getErrorMessage(error)}`
      )
    }

    schema = await getSchema(target, initialHeaders, findings)

    await runDosChecks(target, initialHeaders, findings, schema)

    await runBolaChecks(target, schema, findings)

    scanStatus = 'Completed'
  } catch (error) {
    console.error('[Engine] Error fatal durante el escaneo:', error)
    scanStatus = 'Failed'
    scanError = getErrorMessage(error)
    if (!scanError.startsWith('No se pudo conectar')) {
      findings.push(
        createFinding('Critical', 'Error Fatal Durante el Escaneo', scanError)
      )
    }
  }

  const endTime = new Date()
  const result: ScanResult = {
    scanId:
      typeof crypto !== 'undefined' && crypto.randomUUID
        ? crypto.randomUUID()
        : `scan-${Date.now()}-${Math.random()}`, // Usar ID del Job si se integra con BullMQ
    target: target,
    status: scanStatus,
    findings: findings,
    error: scanError,
    startedAt: startTime,
    completedAt: endTime,
  }

  console.log(
    `[Engine] Escaneo finalizado. Estado: ${result.status}. Hallazgos: ${result.findings.length}.`
  )
  return result
}
