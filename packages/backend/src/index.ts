import express from 'express';
import { Queue, Worker } from 'bullmq';
import IORedis from 'ioredis';
import { Pool } from 'pg'; 
import { runScan } from '@graphql-sentinel/scanner-engine';
import type { ScanTarget, ScanResult } from '@graphql-sentinel/shared-types';

const app = express();
const port = process.env.PORT || 3001;
const redisConnection = new IORedis({
  host: process.env.REDIS_HOST || '127.0.0.1', // Apunta al contenedor Docker o servicio gestionado
  port: parseInt(process.env.REDIS_PORT || '6379'),
  maxRetriesPerRequest: null // Necesario para BullMQ < v4
});

const pgPool = new Pool({
  host: process.env.DB_HOST || '127.0.0.1', // Apunta al contenedor Docker o servicio gestionado
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'sentinel_dev',
  user: process.env.DB_USER || 'user',
  password: process.env.DB_PASSWORD || 'password',
});

// --- Configuración BullMQ ---
const scanQueue = new Queue<ScanTarget>('scan-jobs', { connection: redisConnection });

// --- Worker (Procesador de Trabajos) ---
// Esto debería correr en un proceso separado en producción,
const scanWorker = new Worker<ScanTarget, ScanResult>(
  'scan-jobs',
  async (job) => {
    console.log(`[Worker] Procesando trabajo ${job.id} para target: ${job.data.url}`);
    const target = job.data;
    let result: ScanResult | null = null;
    try {
      result = await runScan(target); // Llama al motor de escaneo

      // Guardar resultado en PostgreSQL
      await pgPool.query(
        'INSERT INTO scan_results(id, target_url, status, findings, completed_at) VALUES($1, $2, $3, $4, $5)',
        [result.scanId, target.url, result.status, JSON.stringify(result.findings), result.completedAt]
      );
       console.log(`[Worker] Trabajo ${job.id} completado y guardado.`);
      return result;
    } catch (error) {
      console.error(`[Worker] Trabajo ${job.id} falló:`, error);
      // Opcional: guardar estado de fallo en DB
      throw error; // Re-lanza para que BullMQ maneje el fallo
    }
  },
  { connection: redisConnection, concurrency: 5 } // Procesar hasta 5 jobs a la vez
);

scanWorker.on('completed', (job, result) => {
  console.log(`Job ${job.id} completed with result: ${result?.findings?.length} findings`);
});

scanWorker.on('failed', (job, err) => {
  console.error(`Job ${job?.id} failed with error ${err.message}`);
});


// --- API Endpoints ---
app.use(express.json());

app.get('/', (req, res) => {
  res.send('GraphQL Sentinel Backend API');
});

// Endpoint para iniciar un escaneo (ej. llamado por el CLI o UI)
app.post('/scans', async (req, res) => {
  const target = req.body as ScanTarget; // ¡Validar input en producción!
  if (!target || !target.url) {
    return res.status(400).send({ error: 'Target URL es requerido' });
  }

  try {
    const job = await scanQueue.add(`scan-<span class="math-inline">\{target\.url\}\-</span>{Date.now()}`, target);
    console.log(`Trabajo añadido a la cola con ID: ${job.id}`);
    // Guardar estado inicial 'Queued' en DB
    await pgPool.query(
      'INSERT INTO scan_results(id, target_url, status) VALUES($1, $2, $3)',
      [job.id, target.url, 'Queued'] // Usamos el ID del Job como ID del scan
    );
    res.status(202).send({ message: 'Escaneo encolado', jobId: job.id });
  } catch (error) {
     console.error('Error al encolar trabajo:', error);
     res.status(500).send({ error: 'Error interno al encolar escaneo' });
  }
});

// Endpoint para obtener resultados de un escaneo
app.get('/scans/:jobId', async (req, res) => {
   const jobId = req.params.jobId;
   try {
     // Consultar estado/resultado desde PostgreSQL
     const dbResult = await pgPool.query('SELECT * FROM scan_results WHERE id = $1', [jobId]);
     if (dbResult.rows.length > 0) {
       const row = dbResult.rows[0];
       // Convertir findings de JSON string a objeto si es necesario
       if (typeof row.findings === 'string') {
           try { row.findings = JSON.parse(row.findings); } catch (e) { /* ignore */ }
       }
       res.status(200).send(row);
     } else {
       res.status(404).send({ message: 'Escaneo no encontrado' });
     }
   } catch (error) {
      console.error('Error al obtener escaneo:', error);
      res.status(500).send({ error: 'Error interno al obtener escaneo' });
   }
});


// --- Iniciar Servidor ---
app.listen(port, () => {
  console.log(`Backend API escuchando en http://localhost:${port}`);
  console.log('Worker esperando trabajos...');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing HTTP server and worker');
  // await server.close(); // Si tienes la instancia del servidor
  await scanWorker.close();
  await redisConnection.quit();
  await pgPool.end();
  console.log('Cleanup complete');
  process.exit(0);
});