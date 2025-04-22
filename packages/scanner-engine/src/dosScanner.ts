import axios, { AxiosError } from 'axios'
import { GraphQLSchema, GraphQLError } from 'graphql'
import type {
  ScanTarget,
  VulnerabilityFinding,
} from '@graphql-sentinel/shared-types'
import { createFinding, getErrorMessage, delay } from './utils'
import {
  generateDeepQuery,
  findListFields,
  buildGraphQLListQuery,
} from './graphUtils'

const DEFAULT_DEPTH_LIMIT = 7
const MAX_LIST_ITEMS_THRESHOLD = 100
const DOS_REQUEST_TIMEOUT = 15000 // Timeout para pruebas DoS
const DOS_LIST_REQUEST_TIMEOUT = 20000 // Timeout más largo para listas
const DOS_INTER_REQUEST_DELAY = 50 // Pausa entre pruebas

/** Ejecuta los chequeos básicos de DoS */
export async function runDosChecks(
  target: ScanTarget,
  headers: Record<string, string>,
  findings: VulnerabilityFinding[],
  schema: GraphQLSchema | null
): Promise<void> {
  // --- Chequeo DoS - Profundidad ---
  console.log('[DosScanner] Ejecutando chequeo de profundidad de query...')
  const deepQuery = generateDeepQuery(DEFAULT_DEPTH_LIMIT, schema)
  try {
    await axios.post(
      target.url,
      { query: deepQuery },
      { headers, timeout: DOS_REQUEST_TIMEOUT }
    )
    findings.push(
      createFinding(
        'Medium',
        'Potencial DoS por Profundidad',
        `Query con profundidad ${DEFAULT_DEPTH_LIMIT} ejecutada con éxito.`
      )
    )
  } catch (error) {
    handlePotentialDosError(error, 'profundidad', findings)
  }
  await delay(DOS_INTER_REQUEST_DELAY) // Pausa

  // --- Chequeo DoS - Falta de Paginación ---
  console.log('[DosScanner] Ejecutando chequeo de falta de paginación...')
  const listFields = findListFields(schema)
  console.log(
    `[DosScanner] Campos de lista encontrados/supuestos: ${listFields.join(', ')}`
  )
  for (const fieldName of listFields) {
    const listQuery = buildGraphQLListQuery(fieldName, schema)
    if (!listQuery) {
      console.warn(
        `[DosScanner] No se pudo construir query para el campo de lista: ${fieldName}`
      )
      continue
    }
    console.log(`[DosScanner] Probando campo de lista: ${fieldName}`)
    try {
      const response = await axios.post<{
        data?: Record<string, any[]>
        errors?: readonly GraphQLError[]
      }>(
        target.url,
        { query: listQuery },
        { headers, timeout: DOS_LIST_REQUEST_TIMEOUT }
      )
      const results = response.data?.data?.[fieldName]
      if (
        response.data?.errors &&
        response.data.errors.some(
          (e) =>
            e.message.toLowerCase().includes('pagination') ||
            e.message.toLowerCase().includes('limit')
        )
      ) {
        console.log(
          `[DosScanner] Chequeo de paginación OK para ${fieldName} (límite requerido).`
        )
      } else if (
        Array.isArray(results) &&
        results.length > MAX_LIST_ITEMS_THRESHOLD
      ) {
        findings.push(
          createFinding(
            'High',
            'Potencial DoS por Falta de Paginación',
            `Query '${fieldName}' devolvió ${results.length} resultados sin paginación.`
          )
        )
      } else if (Array.isArray(results)) {
        console.log(
          `[DosScanner] Query de lista para ${fieldName} OK (${results.length} resultados).`
        )
      } else {
        // Respuesta inesperada pero no error obvio
        console.log(
          `[DosScanner] Respuesta inesperada para ${fieldName} (no es array o sin datos).`
        )
      }
    } catch (error) {
      handlePotentialDosError(error, `lista ${fieldName}`, findings)
    }
    await delay(DOS_INTER_REQUEST_DELAY) // Pausa
  }
  console.log('[DosScanner] Chequeos DoS completados.')
}

/** Maneja errores comunes en chequeos DoS */
function handlePotentialDosError(
  error: unknown,
  checkType: string,
  findings: VulnerabilityFinding[]
) {
  const axiosError = error as AxiosError<{ errors?: GraphQLError[] }>
  const gqlErrors = axiosError.response?.data?.errors
  const errorMessage = getErrorMessage(error)

  if (
    gqlErrors &&
    gqlErrors.some(
      (e) =>
        e.message.toLowerCase().includes('limit') ||
        e.message.toLowerCase().includes('complexity') ||
        e.message.toLowerCase().includes('depth')
    )
  ) {
    console.log(
      `[DosScanner] Chequeo DoS (${checkType}) OK (límite detectado).`
    )
  } else if (errorMessage.toLowerCase().includes('timeout')) {
    findings.push(
      createFinding(
        'Medium',
        `Timeout en Chequeo DoS (${checkType})`,
        `La petición para el chequeo DoS (${checkType}) excedió el tiempo límite.`
      )
    )
  } else {
    console.warn(
      `[DosScanner] Chequeo DoS (${checkType}) resultó en error inesperado:`,
      errorMessage
    )
    findings.push(
      createFinding(
        'Low',
        `Error Inesperado en Chequeo DoS (${checkType})`,
        `La petición causó un error (${errorMessage}).`
      )
    )
  }
}
