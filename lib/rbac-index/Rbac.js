const dottie = require('dottie')
const checkRoleAuthorization = require('./check-role-authorization')
const builtinRoles = require('./builtin-roles')

class Rbac {
  constructor (resourceType, roles, roleMemberships, permissions) {
    const roleIds = roles.map(r => r.roleId)
    const memberships = roleMemberships.filter(
      roleMember => roleIds.indexOf(roleMember.roleId) !== -1 && roleIds.indexOf(roleMember.memberId) !== -1
    )

    const inherits = { }
    const inheritedBy = Object.keys(builtinRoles)
      .reduce((inherited, name) => {
        inherited[builtinRoles[name]] = [builtinRoles[name]]
        return inherited
      }, { })

    for (const roleId of roleIds) {
      inherits[roleId] = inheritedRoles(roleId, memberships)
      inheritedBy[roleId] = superRoles(roleId, memberships)
    }

    const unknownRoles = permissions.map(p => p.roleId).filter(roleId => !Object.prototype.hasOwnProperty.call(inheritedBy, roleId))

    const index = buildIndex(resourceType, permissions, inheritedBy)

    const propOrEmptyArray = (obj, prop) => (prop in obj) ? obj[prop] : []
    const readOnly = () => { throw new Error('Array is read-only') }

    this.index = new Proxy(index, { set: readOnly })
    this.inherits = new Proxy(inherits, { get: propOrEmptyArray, set: readOnly })
    this.inheritedBy = new Proxy(inheritedBy, { get: propOrEmptyArray, set: readOnly })
    this.unknownRoles = new Proxy(unknownRoles, { set: readOnly })
  } // constructor

  checkRoleAuthorization (userId, ownerId, userRoles, resourceType, resourceName, action) {
    return checkRoleAuthorization(userId, ownerId, userRoles, resourceType, resourceName, action, this.index)
  } // checkRoleAuthorization
} // class RbacIndex

function buildIndex (resourceType, permissions, inheritedBy) {
  const index = { }

  const resourceTypeName = `${resourceType}Name`
  for (const permission of permissions) {
    for (const allow of permission.allows) {
      const key = [
        resourceType,
        permission[resourceTypeName],
        allow
      ].join('.')

      const roleList = dottie.get(index, key) || []
      const inheritList = inheritedBy[permission.roleId] || []

      roleList.push(...inheritList)

      dottie.set(index, key, roleList)
    }
  }

  return index
} // buildIndex

function superRoles (rootRoleId, memberships) {
  const inherits = findSuperRoles(rootRoleId, memberships)
  const uniqueInherits = [rootRoleId, ...new Set(inherits)]
  return uniqueInherits
} // superRoles

function findSuperRoles (rootRoleId, memberships) {
  const inherits = []
  const applicableMemberships = memberships.filter(m => m.memberId === rootRoleId)
  for (const membership of applicableMemberships) {
    inherits.push(
      membership.roleId,
      ...findSuperRoles(membership.roleId, memberships)
    )
  }
  return inherits
} // findSuperRoles

function inheritedRoles (rootRoleId, memberships) {
  const inherited = findInheritedRoles(rootRoleId, memberships)
  const uniqueInherited = [rootRoleId, ...new Set(inherited), builtinRoles.Everyone]
  return uniqueInherited
} // inheritedRoles

function findInheritedRoles (rootRoleId, memberships) {
  const inherited = []
  const applicableMemberships = memberships.filter(m => m.roleId === rootRoleId)
  for (const membership of applicableMemberships) {
    inherited.push(
      membership.memberId,
      ...findInheritedRoles(membership.memberId, memberships)
    )
  }
  return inherited
} // findInheritedRoles

module.exports = Rbac
