export interface UserContext {
  id: string // Identificador interno (ej: 'userA', 'adminUser', 'guest')
  authToken: string
  ownedObjectIds: {
    [objectType: string]: string[] // Ej: { 'order': ['123', '124'], 'document': ['docA'] }
  }
}

export interface ScanTarget {
  id: string
  url: string
  schema?: string
  userContexts: UserContext[]
  bolaConfig?: {
    targetObjectTypes?: string[]
  }
}

export interface VulnerabilityFinding {
  id: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
  description: string
  recommendation: string
  evidence?: Record<string, unknown>
}

export interface ScanResult {
  scanId: string
  target: ScanTarget
  status: 'Queued' | 'Running' | 'Completed' | 'Failed'
  findings: VulnerabilityFinding[]
  error?: string
  startedAt?: Date
  completedAt?: Date
}
