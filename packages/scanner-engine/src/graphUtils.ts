import {
  GraphQLSchema,
  isObjectType,
  getNamedType,
  isScalarType,
  GraphQLFieldMap,
  print,
  Kind,
  FieldNode,
  OperationDefinitionNode,
  DocumentNode,
  NameNode,
  ArgumentNode,
  StringValueNode,
  SelectionNode,
  isListType,
  isNonNullType,
  OperationTypeNode,
} from 'graphql'
import { BolaPointOfInterest } from './types'

/** Encuentra queries/mutations con argumentos ID en el schema */
export function findBolaPointsOfInterest(
  schema: GraphQLSchema,
  targetObjectTypes?: string[]
): BolaPointOfInterest[] {
  const points: BolaPointOfInterest[] = []
  const queryType = schema.getQueryType()
  const mutationType = schema.getMutationType()

  const processFields = (
    fields: GraphQLFieldMap<any, any> | null | undefined,
    operation: 'query' | 'mutation'
  ) => {
    if (!fields) return
    for (const fieldName in fields) {
      const field = fields[fieldName]
      const idArg = field.args.find((arg) => {
        const argType = getNamedType(arg.type)
        return (
          argType.toString() === 'ID' || arg.name.toLowerCase().includes('id')
        )
      })

      if (idArg) {
        const returnTypeName = getNamedType(field.type).toString()
        if (
          !targetObjectTypes ||
          targetObjectTypes.length === 0 ||
          targetObjectTypes.includes(returnTypeName)
        ) {
          points.push({
            fieldName,
            idArgName: idArg.name,
            operation,
            returnTypeName,
          })
        }
      }
    }
  }

  processFields(queryType?.getFields(), 'query')
  processFields(mutationType?.getFields(), 'mutation')

  return points
}

/** Construye un nodo de operación GraphQL para BOLA */
export function buildGraphQLOperation(
  point: BolaPointOfInterest,
  objectId: string,
  schema: GraphQLSchema | null
): DocumentNode | null {
  let selectionSet: SelectionNode[] = [
    { kind: Kind.FIELD, name: { kind: Kind.NAME, value: 'id' } },
    { kind: Kind.FIELD, name: { kind: Kind.NAME, value: '__typename' } },
  ]

  if (schema) {
    const operationType =
      point.operation === 'query'
        ? schema.getQueryType()
        : schema.getMutationType()
    const field = operationType?.getFields()[point.fieldName]
    if (field) {
      let returnType = getNamedType(field.type)
      if (isListType(returnType)) returnType = getNamedType(returnType.ofType)
      if (isNonNullType(returnType) && getNamedType(returnType)) {
        returnType = getNamedType(returnType)
      }

      if (isObjectType(returnType)) {
        const fields = returnType.getFields()
        const scalarFields = Object.values(fields)
          .filter((f) => isScalarType(getNamedType(f.type)))
          .slice(0, 3)
        selectionSet.push(
          ...scalarFields.map(
            (f) =>
              ({
                kind: Kind.FIELD,
                name: { kind: Kind.NAME, value: f.name },
              }) as FieldNode
          )
        )
        selectionSet = selectionSet.filter(
          (node, index, self) =>
            index ===
            self.findIndex(
              (n) =>
                (n as FieldNode).name.value === (node as FieldNode).name.value
            )
        )
      }
    }
  }

  const idArgument: ArgumentNode = {
    kind: Kind.ARGUMENT,
    name: { kind: Kind.NAME, value: point.idArgName },
    value: { kind: Kind.STRING, value: objectId },
  }

  const operationDefinition: OperationDefinitionNode = {
    kind: Kind.OPERATION_DEFINITION,
    operation: point.operation as OperationTypeNode,
    selectionSet: {
      kind: Kind.SELECTION_SET,
      selections: [
        {
          kind: Kind.FIELD,
          name: { kind: Kind.NAME, value: point.fieldName },
          arguments: [idArgument],
          selectionSet: {
            kind: Kind.SELECTION_SET,
            selections: selectionSet,
          },
        },
      ],
    },
  }

  return { kind: Kind.DOCUMENT, definitions: [operationDefinition] }
}

/** Genera una query GraphQL profunda, intentando usar el schema */
export function generateDeepQuery(
  depth: number,
  schema: GraphQLSchema | null
): string {
  let path: string[] = []
  let currentType = schema?.getQueryType()
  if (currentType && isObjectType(currentType)) {
    for (let i = 0; i < depth; i++) {
      const fields = currentType?.getFields()
      if (!fields) break
      const nextField = Object.values(fields).find((f) => {
        const fieldType = f.type
        let namedType = getNamedType(fieldType)
        if (
          isListType(fieldType) ||
          (isNonNullType(fieldType) && isListType(fieldType.ofType))
        )
          return false
        if (f.args.some((a) => isNonNullType(a.type))) return false
        return isObjectType(namedType) && namedType.name !== currentType?.name
      })

      if (nextField) {
        path.push(nextField.name)
        currentType = getNamedType(nextField.type) as any
      } else {
        break
      }
    }
  }

  if (path.length > 0) {
    let query = '{'
    for (const fieldName of path) {
      query += ` ${fieldName} {`
    }
    query += ' id __typename '
    for (let i = 0; i < path.length; i++) {
      query += ' }'
    }
    query += ' }'
    console.log(
      `[Engine] Generada query profunda basada en schema (profundidad ${path.length}): ${query.substring(0, 100)}...`
    )
    return query
  } else {
    console.log(
      '[Engine] Usando query profunda genérica (schema no útil/disponible).'
    )
    let query = '{'
    let current = 'node'
    for (let i = 0; i < depth; i++) {
      query += ` ${current} {`
      current = `child${i}`
    }
    query += ' id __typename '
    for (let i = 0; i < depth; i++) {
      query += ' }'
    }
    query += ' }'
    return query
  }
}

/** Encuentra campos que devuelven listas en el schema */
export function findListFields(schema: GraphQLSchema | null): string[] {
  const listFields: string[] = []
  const commonListNames = [
    'users',
    'posts',
    'items',
    'orders',
    'products',
    'nodes',
    'edges',
    'connections',
    'list',
    'all',
    'get',
  ]
  if (!schema) return commonListNames

  const queryType = schema.getQueryType()
  if (queryType) {
    const fields = queryType.getFields()
    for (const fieldName in fields) {
      const field = fields[fieldName]
      let unwrappedType = field.type
      let isList = false
      if (isNonNullType(unwrappedType)) unwrappedType = unwrappedType.ofType
      if (isListType(unwrappedType)) {
        isList = true
        unwrappedType = unwrappedType.ofType
        if (isNonNullType(unwrappedType)) unwrappedType = unwrappedType.ofType
      }

      const requiredArgs = field.args.filter((arg) => isNonNullType(arg.type))
      const hasRequiredNonPaginationArgs = requiredArgs.some(
        (arg) =>
          !['first', 'last', 'before', 'after', 'limit', 'offset'].includes(
            arg.name.toLowerCase()
          )
      )

      if (isList && !hasRequiredNonPaginationArgs) {
        listFields.push(fieldName)
      }
    }
  }
  return listFields.length > 0 ? listFields : commonListNames
}

/** Construye una query simple para un campo de lista pidiendo campos escalares */
export function buildGraphQLListQuery(
  fieldName: string,
  schema: GraphQLSchema | null
): string | null {
  let selectionSet: SelectionNode[] = [
    { kind: Kind.FIELD, name: { kind: Kind.NAME, value: 'id' } },
    { kind: Kind.FIELD, name: { kind: Kind.NAME, value: '__typename' } },
  ]

  if (schema) {
    const queryType = schema.getQueryType()
    const field = queryType?.getFields()[fieldName]
    if (field) {
      let returnType = getNamedType(field.type)
      if (isListType(returnType)) returnType = getNamedType(returnType.ofType)
      if (isNonNullType(returnType))
        returnType = getNamedType(returnType.ofType)

      if (isObjectType(returnType)) {
        const fields = returnType.getFields()
        const scalarFields = Object.values(fields)
          .filter((f) => isScalarType(getNamedType(f.type)))
          .slice(0, 3)
        selectionSet.push(
          ...scalarFields.map(
            (f) =>
              ({
                kind: Kind.FIELD,
                name: { kind: Kind.NAME, value: f.name },
              }) as FieldNode
          )
        )
        selectionSet = selectionSet.filter(
          (node, index, self) =>
            index ===
            self.findIndex(
              (n) =>
                (n as FieldNode).name.value === (node as FieldNode).name.value
            )
        )
      }
    }
  }

  const operationDefinition: OperationDefinitionNode = {
    kind: Kind.OPERATION_DEFINITION,
    operation: 'query' as OperationTypeNode,
    selectionSet: {
      kind: Kind.SELECTION_SET,
      selections: [
        {
          kind: Kind.FIELD,
          name: { kind: Kind.NAME, value: fieldName },
          selectionSet: {
            kind: Kind.SELECTION_SET,
            selections: selectionSet,
          },
        },
      ],
    },
  }
  return print({ kind: Kind.DOCUMENT, definitions: [operationDefinition] })
}

/** Intenta inferir el tipo de objeto del nombre del campo (heurística simple) */
export function inferObjectTypeFromFieldName(fieldName: string): string {
  let typeName = fieldName.replace(/^(get|find|list|all)/i, '')
  typeName = typeName.replace(/(ById|Connection|Edge|s)$/i, '')
  // Si queda vacío, devuelve un genérico o el original
  if (!typeName) return 'Object'
  return typeName.charAt(0).toUpperCase() + typeName.slice(1)
}
