import axios, { AxiosError } from 'axios';
import { buildSchema, getIntrospectionQuery, IntrospectionQuery, GraphQLError, GraphQLSchema } from 'graphql';
import type { ScanTarget, ScanResult, VulnerabilityFinding } from '@graphql-sentinel/shared-types'; 

const DEFAULT_DEPTH_LIMIT = 7; // Límite de profundidad para testear DoS
const MAX_LIST_ITEMS_THRESHOLD = 100; // Umbral para detectar falta de paginación

/**
 * Función principal para ejecutar un escaneo de seguridad en un target.
 * @param target - Información del API a escanear.
 * @returns El resultado del escaneo con los hallazgos.
 */
export async function runScan(target: ScanTarget): Promise<ScanResult> {
  console.log(`[Engine] Iniciando escaneo para: ${target.url}`);
  const startTime = new Date();
  const findings: VulnerabilityFinding[] = [];
  let schema: GraphQLSchema | null = null;
  let scanStatus: ScanResult['status'] = 'Running';
  let scanError: string | undefined = undefined;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (target.authToken) {
    headers['Authorization'] = `Bearer ${target.authToken}`;
  }

  try {
    // --- Paso 2.1: Chequeo de Conectividad Básica ---
    try {
      console.log('[Engine] Verificando conectividad...');
      // Intenta una query simple para ver si el endpoint responde
      await axios.post(
        target.url,
        { query: '{ __typename }' },
        { headers, timeout: 5000 } // Timeout corto para conectividad
      );
      console.log('[Engine] Conectividad OK.');
    } catch (error) {
      console.error('[Engine] Error de conectividad:', error);
      throw new Error(`No se pudo conectar a ${target.url}. Verifica la URL y la red.`);
    }

    // --- Paso 2.2: Obtener Schema (Introspection) ---
    // TODO: Implementar carga de schema desde archivo/URL si target.schema lo especifica
    try {
      console.log('[Engine] Intentando obtener schema vía Introspection...');
      const introspectionQuery = getIntrospectionQuery();
      const response = await axios.post<{ data: IntrospectionQuery; errors?: readonly GraphQLError[] }>(
        target.url,
        { query: introspectionQuery },
        { headers, timeout: 10000 }
      );

      if (response.data.errors) {
        console.warn('[Engine] Introspection query devolvió errores:', response.data.errors);
        findings.push(createFinding('Info', 'Introspection Query con Errores', 'La introspection query devolvió errores, podría indicar problemas en el schema o configuración.'));
      }
      if (response.data.data) {
        schema = buildSchema(response.data.data as any); // Construye el schema
        console.log('[Engine] Schema obtenido y parseado correctamente.');
         findings.push(createFinding('Info', 'Introspection Habilitada', 'La API permite introspection queries. Considera deshabilitarla en producción si no es necesaria.'));
      } else {
         console.warn('[Engine] No se pudo obtener el schema vía Introspection (no data).');
         findings.push(createFinding('Low', 'Introspection Deshabilitada o Fallida', 'No se pudo obtener el schema vía Introspection. El análisis será menos preciso.'));
      }
    } catch (error) {
      console.warn('[Engine] Falló el intento de Introspection:', getErrorMessage(error));
      findings.push(createFinding('Low', 'Introspection Deshabilitada o Fallida', `No se pudo obtener el schema vía Introspection (${getErrorMessage(error)}). El análisis será menos preciso.`));
    }

    // --- Paso 2.3: Chequeo DoS - Profundidad ---
    console.log('[Engine] Ejecutando chequeo de profundidad de query...');
    // TODO: Generar query profunda basada en schema si está disponible. Por ahora, una genérica.
    const deepQuery = generateDeepQuery(DEFAULT_DEPTH_LIMIT);
    try {
      await axios.post(target.url, { query: deepQuery }, { headers, timeout: 15000 });
      // Si la query profunda tiene ÉXITO, es una señal de alerta.
      findings.push(createFinding('Medium', 'Potencial DoS por Profundidad', `Una query con profundidad ${DEFAULT_DEPTH_LIMIT} fue ejecutada con éxito. La API podría ser vulnerable a DoS si no tiene límites de profundidad estrictos.`));
    } catch (error) {
      const axiosError = error as AxiosError<{ errors?: GraphQLError[] }>;
      const gqlErrors = axiosError.response?.data?.errors;
      if (gqlErrors && gqlErrors.some(e => e.message.toLowerCase().includes('depth limit'))) {
        console.log(`[Engine] Chequeo de profundidad OK (límite detectado).`);
      } else {
        // Otro tipo de error, podría ser timeout o error del servidor, lo cual también es sospechoso
        console.warn('[Engine] Query profunda resultó en error inesperado:', getErrorMessage(error));
         findings.push(createFinding('Low', 'Error Inesperado en Query Profunda', `La query profunda causó un error (${getErrorMessage(error)}), podría indicar falta de protección DoS o timeout.`));
      }
    }

    // --- Paso 2.4: Chequeo DoS - Falta de Paginación ---
    console.log('[Engine] Ejecutando chequeo de falta de paginación...');
    // TODO: Identificar campos de lista desde el schema. Por ahora, nombres comunes.
    const listFieldNames = ['users', 'posts', 'items', 'orders', 'products', 'nodes']; // Añadir más si es necesario
    for (const fieldName of listFieldNames) {
      // Intenta consultar un campo de lista sin argumentos de paginación
      // Pide solo un campo simple como 'id' o '__typename' para minimizar datos
      const listQuery = `query { ${fieldName} { id __typename } }`;
      try {
        const response = await axios.post<{ data?: Record<string, any[]>; errors?: readonly GraphQLError[] }>(
          target.url,
          { query: listQuery },
          { headers, timeout: 20000 } // Timeout más largo por si devuelve muchos datos
        );

        const results = response.data?.data?.[fieldName];
        if (response.data?.errors && response.data.errors.some(e => e.message.toLowerCase().includes('pagination') || e.message.toLowerCase().includes('limit'))) {
           console.log(`[Engine] Chequeo de paginación OK para ${fieldName} (límite requerido).`);
        } else if (Array.isArray(results) && results.length > MAX_LIST_ITEMS_THRESHOLD) {
          // Si devuelve muchos resultados sin paginación, es un hallazgo.
          findings.push(createFinding('High', 'Potencial DoS por Falta de Paginación', `La query del campo '${fieldName}' devolvió ${results.length} resultados sin requerir paginación. Podría usarse para sobrecargar el servidor.`));
        } else if (Array.isArray(results)) {
           console.log(`[Engine] Query de lista para ${fieldName} OK (${results.length} resultados).`);
        }
      } catch (error) {
         // Si falla (ej. timeout), también puede ser indicativo de problema
         console.warn(`[Engine] Query de lista para ${fieldName} falló:`, getErrorMessage(error));
         findings.push(createFinding('Medium', 'Error/Timeout en Query de Lista sin Paginación', `La query del campo '${fieldName}' sin paginación causó un error (${getErrorMessage(error)}), podría indicar falta de protección DoS.`));
      }
    }

    // --- Paso 2.5: Chequeo BOLA (V0.1 - Muy Básico) ---
    console.log('[Engine] Ejecutando chequeo BOLA básico...');
    // !! ESTA ES UNA IMPLEMENTACIÓN MUY SIMPLIFICADA !!
    // Requiere configuración externa para saber qué IDs/Tokens usar para UserA y UserB
    // y qué queries/campos son sensibles o específicos de usuario.
    const userA_token = target.authToken; // Asume el token principal es UserA
    const userB_id = 'USER_B_ID_PLACEHOLDER'; // !! NECESITA CONFIGURACIÓN !!
    const targetQueryField = 'user'; // Asume que hay un query 'user(id: ID)'
    const sensitiveField = 'email'; // Asume que 'email' es un campo sensible

    if (userA_token && userB_id !== 'USER_B_ID_PLACEHOLDER') {
        const bolaQuery = `query { ${targetQueryField}(id: "${userB_id}") { ${sensitiveField} } }`;
        try {
            const response = await axios.post<{ data?: Record<string, any>; errors?: readonly GraphQLError[] }>(
                target.url,
                { query: bolaQuery },
                { headers } // Usa headers con token de UserA
            );

            const responseData = response.data?.data?.[targetQueryField];
            const responseErrors = response.data?.errors;

            if (responseErrors && responseErrors.some(e => e.message.toLowerCase().includes('unauthorized') || e.message.toLowerCase().includes('forbidden') || e.message.toLowerCase().includes('not found'))) {
                console.log(`[Engine] Chequeo BOLA OK para ${targetQueryField}(id: ${userB_id}) (Acceso denegado como esperado).`);
            } else if (responseData && responseData[sensitiveField]) {
                // ¡Alerta! UserA pudo obtener datos (ej: email) de UserB
                findings.push(createFinding('Critical', 'Potencial BOLA Detectado', `Usuario autenticado (UserA) pudo acceder al campo '${sensitiveField}' del objeto '${targetQueryField}' con ID '${userB_id}' (UserB).`));
            } else {
                 console.log(`[Engine] Chequeo BOLA para ${targetQueryField}(id: ${userB_id}) no concluyente (respuesta inesperada o campo no encontrado).`);
            }
        } catch (error) {
            // Errores aquí también pueden ocultar problemas, pero es difícil asegurarlo
            console.warn(`[Engine] Chequeo BOLA para ${targetQueryField}(id: ${userB_id}) falló con error:`, getErrorMessage(error));
        }
    } else {
        console.log('[Engine] Saltando chequeo BOLA (falta configuración de UserA/UserB/IDs).');
    }

    // --- Finalización ---
    scanStatus = 'Completed';

  } catch (error) {
    console.error('[Engine] Error fatal durante el escaneo:', error);
    scanStatus = 'Failed';
    scanError = getErrorMessage(error);
  }

  // --- Paso 2.6 y 2.7: Agregar y Devolver Resultados ---
  const endTime = new Date();
  const result: ScanResult = {
    scanId: crypto.randomUUID(), // Usar ID del Job si se integra con BullMQ
    target: target,
    status: scanStatus,
    findings: findings,
    error: scanError,
    startedAt: startTime,
    completedAt: endTime,
  };

  console.log(`[Engine] Escaneo finalizado. Estado: ${result.status}. Hallazgos: ${result.findings.length}.`);
  return result;
}


// --- Funciones Helper ---

/** Helper para crear objetos de hallazgo */
function createFinding(
  severity: VulnerabilityFinding['severity'],
  description: string,
  recommendation: string,
  evidence?: Record<string, unknown>
): VulnerabilityFinding {
  return {
    id: crypto.randomUUID(),
    severity,
    description,
    recommendation,
    evidence,
  };
}

/** Helper para generar una query GraphQL profunda (simplificado) */
function generateDeepQuery(depth: number): string {
    let query = '{';
    let current = 'node';
    for (let i = 0; i < depth; i++) {
        query += ` ${current} {`;
        current = `child${i}`;
    }
    query += ' id '; // Campo final
    for (let i = 0; i < depth; i++) {
        query += ' }';
    }
    query += ' }';
    // Ejemplo para depth 3: { node { child0 { child1 { id } } } }
    // ¡Esto es muy genérico y puede no funcionar en todas las APIs!
    // Idealmente se basaría en el schema real.
    return query;
}

/** Helper para obtener un mensaje de error legible */
function getErrorMessage(error: unknown): string {
  if (error instanceof AxiosError) {
    // Intenta obtener info específica de Axios
    if (error.response?.data?.errors) {
      // Errores GraphQL
      return `GraphQL Error: ${error.response.data.errors.map((e: any) => e.message).join(', ')}`;
    }
    if (error.response?.data?.message) {
       return `API Error ${error.response.status}: ${error.response.data.message}`;
    }
     if (error.response?.statusText) {
       return `HTTP Error ${error.response.status}: ${error.response.statusText}`;
    }
    if (error.message.includes('timeout')) {
        return 'Timeout de la petición';
    }
  }
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

