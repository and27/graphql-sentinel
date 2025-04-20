export interface ScanTarget {
    id: string;
    url: string; // Endpoint GraphQL o base URL REST
    schema?: string; // Contenido del schema o URL/path
    authToken?: string; // Para APIs autenticadas
  }
  
  export interface VulnerabilityFinding {
    id: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
    description: string;
    recommendation: string;
    evidence?: Record<string, unknown>; 
  }
  
  export interface ScanResult {
    scanId: string;
    target: ScanTarget;
    status: 'Queued' | 'Running' | 'Completed' | 'Failed';
    findings: VulnerabilityFinding[];
    error?: string;
    startedAt?: Date;
    completedAt?: Date;
  }
  