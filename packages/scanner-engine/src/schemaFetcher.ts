import axios from 'axios'
import {
  buildClientSchema,
  getIntrospectionQuery,
  IntrospectionQuery,
  GraphQLError,
  GraphQLSchema,
} from 'graphql'
import type {
  ScanTarget,
  VulnerabilityFinding,
} from '@graphql-sentinel/shared-types'
import { createFinding, getErrorMessage } from './utils'

/** Intenta obtener el schema vía Introspection o desde config */
export async function getSchema(
  target: ScanTarget,
  headers: Record<string, string>,
  findings: VulnerabilityFinding[]
): Promise<GraphQLSchema | null> {
  // TODO: Implementar carga desde target.schema (archivo/URL)
  // Por ahora, solo intenta Introspection
  try {
    console.log(
      '[SchemaFetcher] Intentando obtener schema vía Introspection...'
    )
    const introspectionQuery = getIntrospectionQuery({ descriptions: false })
    const response = await axios.post<{
      data?: IntrospectionQuery
      errors?: readonly GraphQLError[]
    }>(target.url, { query: introspectionQuery }, { headers, timeout: 15000 })

    if (response.data?.errors) {
      console.warn(
        '[SchemaFetcher] Introspection query devolvió errores:',
        response.data.errors
      )
      findings.push(
        createFinding(
          'Info',
          'Introspection Query con Errores',
          'La introspection query devolvió errores.'
        )
      )
    }
    if (response.data?.data) {
      const schema = buildClientSchema(response.data.data)
      console.log('[SchemaFetcher] Schema obtenido y parseado correctamente.')
      findings.push(
        createFinding(
          'Info',
          'Introspection Habilitada',
          'La API permite introspection queries. Considera deshabilitarla en producción.'
        )
      )
      return schema
    } else {
      console.warn(
        '[SchemaFetcher] No se pudo obtener el schema vía Introspection (no data).'
      )
      findings.push(
        createFinding(
          'Low',
          'Introspection Deshabilitada o Fallida',
          'No se pudo obtener el schema vía Introspection.'
        )
      )
      return null
    }
  } catch (error) {
    console.warn(
      '[SchemaFetcher] Falló el intento de Introspection:',
      getErrorMessage(error)
    )
    findings.push(
      createFinding(
        'Low',
        'Introspection Deshabilitada o Fallida',
        `No se pudo obtener el schema vía Introspection (${getErrorMessage(error)}).`
      )
    )
    return null
  }
}
