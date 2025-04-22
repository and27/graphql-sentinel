import axios, { AxiosError } from 'axios'
import { GraphQLSchema, GraphQLError, print } from 'graphql'
import type {
  ScanTarget,
  VulnerabilityFinding,
  UserContext,
} from '@graphql-sentinel/shared-types'
import { createFinding, getErrorMessage, buildHeaders, delay } from './utils'

import { BolaPointOfInterest } from './types'
import {
  buildGraphQLOperation,
  findBolaPointsOfInterest,
  inferObjectTypeFromFieldName,
} from './graphUtils'

const BOLA_REQUEST_TIMEOUT = 15000
const BOLA_INTER_REQUEST_DELAY = 50

/** Ejecuta el ciclo completo de pruebas BOLA */
export async function runBolaChecks(
  target: ScanTarget,
  schema: GraphQLSchema | null,
  findings: VulnerabilityFinding[]
): Promise<void> {
  const canRunBola = target.userContexts && target.userContexts.length >= 2
  if (!canRunBola) {
    console.log(
      '[BolaTester] Saltando chequeo BOLA (se requieren >= 2 userContexts).'
    )
    return
  }
  if (!schema) {
    console.log('[BolaTester] Saltando chequeo BOLA (schema no disponible).')
    return
  }

  console.log('[BolaTester] Descubriendo puntos de prueba BOLA...')
  const bolaPoints = findBolaPointsOfInterest(
    schema,
    target.bolaConfig?.targetObjectTypes
  )
  console.log(
    `[BolaTester] ${bolaPoints.length} puntos de prueba BOLA identificados.`
  )

  if (bolaPoints.length === 0) {
    // Añadir finding informativo solo si no se filtró por tipos específicos
    if (
      !target.bolaConfig?.targetObjectTypes ||
      target.bolaConfig.targetObjectTypes.length === 0
    ) {
      findings.push(
        createFinding(
          'Info',
          'No se encontraron puntos de prueba BOLA',
          'El análisis del schema no identificó queries/mutations obvias con argumentos ID para probar BOLA.'
        )
      )
    } else {
      findings.push(
        createFinding(
          'Info',
          'No se encontraron puntos de prueba BOLA para los tipos especificados',
          `No se encontraron queries/mutations con argumentos ID que devuelvan los tipos [${target.bolaConfig.targetObjectTypes.join(', ')}] para probar BOLA.`
        )
      )
    }
    console.log(
      '[BolaTester] Saltando ciclo BOLA (no se identificaron puntos de prueba).'
    )
    return
  }

  console.log('[BolaTester] Iniciando ciclo de pruebas BOLA avanzado...')
  const testedVictimObjects = new Set<string>()

  for (const attackerContext of target.userContexts) {
    console.log(`[BolaTester] Probando como atacante: ${attackerContext.id}`)
    const attackerHeaders = buildHeaders(attackerContext.authToken)

    for (const victimContext of target.userContexts) {
      if (attackerContext.id === victimContext.id) continue
      // console.log(`  [BolaTester] Intentando acceder a objetos de víctima: ${victimContext.id}`);

      for (const point of bolaPoints) {
        const objectType =
          point.returnTypeName || inferObjectTypeFromFieldName(point.fieldName)
        const victimObjectIds = victimContext.ownedObjectIds[objectType] || []

        if (victimObjectIds.length === 0) continue

        for (const victimObjectId of victimObjectIds) {
          const testKey = `${attackerContext.id}-${point.operation}-${point.fieldName}-${victimObjectId}`
          if (testedVictimObjects.has(testKey)) continue
          testedVictimObjects.add(testKey)

          // console.log(`      [BolaTester] Probando ${point.operation} ${point.fieldName}(${point.idArgName}: "${victimObjectId}")`);

          const operationNode = buildGraphQLOperation(
            point,
            victimObjectId,
            schema
          )
          if (!operationNode) {
            console.warn(
              `      [BolaTester] No se pudo construir la operación para ${point.fieldName}`
            )
            continue
          }

          const query = print(operationNode)

          try {
            const response = await axios.post<{
              data?: Record<string, any>
              errors?: readonly GraphQLError[]
            }>(
              target.url,
              { query },
              { headers: attackerHeaders, timeout: BOLA_REQUEST_TIMEOUT }
            )

            const responseData = response.data?.data?.[point.fieldName]
            const responseErrors = response.data?.errors

            analyzeBolaResponse(
              findings,
              attackerContext,
              victimContext,
              point,
              victimObjectId,
              responseData,
              responseErrors,
              query
            )
          } catch (error) {
            // console.warn(`      [BolaTester] Error en prueba BOLA (${point.fieldName}, id: ${victimObjectId}): ${getErrorMessage(error)}`);
            if (
              error instanceof AxiosError &&
              (error.response?.status === 401 || error.response?.status === 403)
            ) {
              // Acceso denegado a nivel HTTP, es bueno.
            } else {
              findings.push(
                createFinding(
                  'Low',
                  `Error Inesperado en Prueba BOLA (${point.fieldName})`,
                  `La petición BOLA para el objeto ${victimObjectId} de ${victimContext.id} (atacante ${attackerContext.id}) falló con: ${getErrorMessage(error)}`,
                  { query }
                )
              )
            }
          }
          await delay(BOLA_INTER_REQUEST_DELAY)
        }
      }
    }
  }
  console.log('[BolaTester] Ciclo de pruebas BOLA avanzado completado.')
}

/** Analiza la respuesta de un intento de BOLA */
function analyzeBolaResponse(
  findings: VulnerabilityFinding[],
  attacker: UserContext,
  victim: UserContext,
  point: BolaPointOfInterest,
  victimObjectId: string,
  responseData: any,
  responseErrors: readonly GraphQLError[] | undefined,
  query: string
) {
  const testDesc = `${point.operation} ${point.fieldName}(${point.idArgName}: "${victimObjectId}")`

  if (
    responseErrors &&
    responseErrors.some(
      (e) =>
        e.message.toLowerCase().includes('unauthorized') ||
        e.message.toLowerCase().includes('forbidden') ||
        e.message.toLowerCase().includes('access denied') ||
        (e.message.toLowerCase().includes('not found') && !responseData) // Considerar 404/null como posible denegación
    )
  ) {
    // Acceso denegado correctamente
    // console.log(`      [BolaTester] BOLA Check OK para ${testDesc} (Acceso denegado).`);
  } else if (
    responseData &&
    typeof responseData === 'object' &&
    responseData !== null
  ) {
    // Éxito, verificar si realmente obtuvo datos útiles
    const keys = Object.keys(responseData).filter((k) => k !== '__typename')
    if (keys.length > 0 || Array.isArray(responseData)) {
      // Considerar arrays no vacíos como éxito también
      // Si es una mutación, el éxito es más crítico aunque no devuelva muchos datos
      const severity = point.operation === 'mutation' ? 'Critical' : 'High'
      findings.push(
        createFinding(
          severity,
          'BOLA Detectado',
          `Usuario '${attacker.id}' pudo ejecutar ${testDesc} sobre objeto de '${victim.id}' y obtuvo/modificó datos. Verificar autorización en el resolver.`,
          { query: query, response: responseData }
        )
      )
    } else {
      // console.log(`      [BolaTester] BOLA Check OK para ${testDesc} (Respuesta vacía/solo typename).`);
    }
  } else if (responseErrors) {
    console.warn(
      `      [BolaTester] BOLA Check para ${testDesc} devolvió errores inesperados: ${responseErrors.map((e) => e.message).join(', ')}`
    )
    // findings.push(
    //   createFinding(
    //     'Low',
    //     `Error Inesperado en Prueba BOLA (${point.fieldName})`,
    //     `La petición BOLA para el objeto ${victimObjectId} de ${victimContext.id} (atacante ${attackerContext.id}) devolvió errores GraphQL: ${responseErrors.map((e) => e.message).join(', ')}`,
    //     { query }
    //   )
    // )
  } else {
    // Respuesta inesperada (ej. null sin errores GraphQL)
    // console.log(`      [BolaTester] BOLA Check para ${testDesc} no concluyente (respuesta inesperada: ${JSON.stringify(responseData)}).`);
  }
}
