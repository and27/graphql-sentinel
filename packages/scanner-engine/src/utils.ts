import axios, { AxiosError } from 'axios'
import { GraphQLError } from 'graphql'
import type { VulnerabilityFinding } from '@graphql-sentinel/shared-types'

/** Helper para crear objetos de hallazgo */
export function createFinding(
  severity: VulnerabilityFinding['severity'],
  description: string,
  recommendation: string,
  evidence?: Record<string, unknown>
): VulnerabilityFinding {
  // Asegura que crypto esté disponible (Node >= 14.17) o usa un fallback
  const id =
    typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : `finding-${Date.now()}-${Math.random()}`
  return { id, severity, description, recommendation, evidence }
}

/** Helper para obtener un mensaje de error legible */
export function getErrorMessage(error: unknown): string {
  if (error instanceof AxiosError) {
    if (
      error.response?.data?.errors &&
      Array.isArray(error.response.data.errors)
    ) {
      return `GraphQL Error: ${error.response.data.errors.map((e: any) => e.message || String(e)).join(', ')}`
    }
    const responseData = error.response?.data as any
    if (responseData?.message)
      return `API Error ${error.response?.status}: ${responseData.message}`
    if (error.response?.statusText)
      return `HTTP Error ${error.response?.status}: ${error.response.statusText}`
    if (error.code) return `Network Error: ${error.code}`
    // Check for timeout specifically
    if (
      error.code === 'ECONNABORTED' ||
      (error.message && error.message.toLowerCase().includes('timeout'))
    ) {
      return 'Timeout de la petición'
    }
  }
  if (error instanceof Error) return error.message
  if (typeof error === 'string') return error
  return 'Error desconocido'
}

/** Construye el objeto de headers para Axios */
export function buildHeaders(authToken?: string): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  }
  if (authToken) {
    // Asume Bearer, podría necesitar configuración para otros esquemas
    headers['Authorization'] = `Bearer ${authToken}`
  }
  return headers
}

/** Pausa la ejecución por un número de milisegundos */
export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
