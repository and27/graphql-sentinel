export interface BolaPointOfInterest {
  fieldName: string
  idArgName: string
  operation: 'query' | 'mutation'
  returnTypeName?: string
}
