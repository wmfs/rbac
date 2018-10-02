const RbacIndex = require('./rbac-index/Rbac')

RbacIndex.builtInRoles = Object.values(require('./rbac-index/builtin-roles'))

module.exports = RbacIndex
