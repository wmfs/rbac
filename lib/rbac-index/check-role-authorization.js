const dottie = require('dottie')
const debug = require('debug')('rbac')
const builtinRoles = require('./builtin-roles')

function checkRoleAuthorization (userId, ownerId, userRoles, resourceType, resourceName, action, rbacIndex) {
  const requiredRoles = getRequiredRoleList(resourceType, resourceName, action, rbacIndex)
  const result = checker(userId, ownerId, userRoles, requiredRoles)
  addDebug(userId, userRoles, resourceType, resourceName, action, requiredRoles, result)
  return result
} // checkRoleAuthorization

function getRequiredRoleList (resourceType, resourceName, action, rbacIndex) {
  // What roles will allow this?
  const unrestricted = dottie.get(rbacIndex, '*.*.*') || []
  const unrestrictedInADomain = dottie.get(rbacIndex, `${resourceType}.*.*`) || []
  const anyActionOnASpecificResource = dottie.get(rbacIndex, `${resourceType}.${resourceName}.*`) || []
  const anyDomainResourceForASpecificAction = dottie.get(rbacIndex, `${resourceType}.*.${action}`) || []
  const specific = dottie.get(rbacIndex, `${resourceType}.${resourceName}.${action}`) || []

  return unrestricted.concat(
    unrestrictedInADomain,
    anyActionOnASpecificResource,
    anyDomainResourceForASpecificAction,
    specific
  )
} // getRequiredRoleList

function checker (uid, ownerId, userRoles, requiredRoleList) {
  if (requiredRoleList.length === 0) {
    return false
  }

  if (requiredRoleList.includes(builtinRoles.Everyone)) {
    return true
  }

  if (uid && requiredRoleList.includes(builtinRoles.Authenticated)) {
    return true
  }

  for (const role of userRoles) {
    if (requiredRoleList.includes(role)) return true
  }

  // TODO: roles.Owner is actually a finer-grained restriction over usual roles. Not this.
  return requiredRoleList.includes(builtinRoles.Owner) &&
    uid &&
    (ownerId === uid)
} // checker

function addDebug (uid, userRoles, resourceType, resourceName, action, requiredRoleList, result) {
  const text = `User '${uid}' is attempting to '${action}' on ${resourceType} '${resourceName}'... ` +
    `\n\twhich requires one of these roles: ${JSON.stringify(requiredRoleList)},` +
    `\n\tand user has these roles: ${JSON.stringify(userRoles)}. \n\t` +
    (result ? 'Access permitted!' : 'Access denied!')
  debug(text)
} // addDebug

module.exports = checkRoleAuthorization
