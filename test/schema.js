'use strict'

const test = require('ava')

const schema = require('../src/schema.json')
const providers = require('../src/providers.json')

const resolveRef = (root, ref) => {
  if (!ref.startsWith('#/')) {
    throw new Error(`Unsupported ref: ${ref}`)
  }
  return ref
    .slice(2)
    .split('/')
    .reduce((acc, key) => acc[key], root)
}

const validate = (value, definition, root, path = '$') => {
  if (definition.$ref) {
    return validate(value, resolveRef(root, definition.$ref), root, path)
  }

  if (definition.oneOf) {
    const matches = definition.oneOf.filter(
      option => validate(value, option, root, path).length === 0
    )
    return matches.length === 1
      ? []
      : [`${path} should match exactly one schema in oneOf`]
  }

  const errors = []

  if (definition.type === 'object') {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return [`${path} should be an object`]
    }
    for (const required of definition.required || []) {
      if (!(required in value)) {
        errors.push(`${path} is missing required property "${required}"`)
      }
    }
    if (definition.additionalProperties === false) {
      const allowed = new Set(Object.keys(definition.properties || {}))
      for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
          errors.push(`${path}.${key} is not allowed`)
        }
      }
    }
    for (const [key, propertySchema] of Object.entries(
      definition.properties || {}
    )) {
      if (key in value) {
        errors.push(
          ...validate(value[key], propertySchema, root, `${path}.${key}`)
        )
      }
    }
    return errors
  }

  if (definition.type === 'array') {
    if (!Array.isArray(value)) {
      return [`${path} should be an array`]
    }
    if (
      definition.minItems !== undefined &&
      value.length < definition.minItems
    ) {
      errors.push(
        `${path} should contain at least ${definition.minItems} items`
      )
    }
    if (definition.items) {
      value.forEach((item, index) => {
        errors.push(
          ...validate(item, definition.items, root, `${path}[${index}]`)
        )
      })
    }
    return errors
  }

  if (definition.type === 'string') {
    if (typeof value !== 'string') {
      return [`${path} should be a string`]
    }
    if (definition.pattern && !new RegExp(definition.pattern).test(value)) {
      errors.push(`${path} does not match pattern ${definition.pattern}`)
    }
    if (definition.format === 'regex') {
      try {
        // eslint-disable-next-line no-new
        new RegExp(value)
      } catch {
        errors.push(`${path} should contain a valid regex pattern`)
      }
    }
  }

  if (definition.type === 'integer') {
    if (!Number.isInteger(value)) {
      errors.push(`${path} should be an integer`)
    }
  }

  if (definition.enum && !definition.enum.includes(value)) {
    errors.push(`${path} should be one of: ${definition.enum.join(', ')}`)
  }

  if (definition.const !== undefined && value !== definition.const) {
    errors.push(`${path} should be exactly ${definition.const}`)
  }

  return errors
}

test('providers json conforms to providers schema', t => {
  const errors = validate(providers, schema, schema)
  t.deepEqual(errors, [])
})
