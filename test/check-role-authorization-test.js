/* eslint-env mocha */

const expect = require('chai').expect
const RbacIndex = require('../lib/rbac-index/Rbac')

const rbacIndex = new RbacIndex(
  {
    'roleMemberships': [
      {
        'roleId': 'tymlyTest_boss',
        'memberType': 'role',
        'memberId': 'tymlyTest_teamLeader'
      },
      {
        'roleId': 'tymlyTest_teamLeader',
        'memberType': 'role',
        'memberId': 'tymlyTest_developer'
      }
    ],
    'permissions': [
      {
        'stateMachineName': 'tymlyTest_purgeSite_1_0',
        'roleId': 'tymlyTest_boss',
        'allows': [ 'create' ]
      },
      {
        'stateMachineName': 'tymlyTest_deletePost_1_0',
        'roleId': 'tymlyTest_boss',
        'allows': [ 'cancel' ]
      },
      {
        'stateMachineName': 'tymlyTest_createPost_1_0',
        'roleId': 'tymlyTest_developer',
        'allows': [ 'cancel' ]
      },
      {
        'stateMachineName': 'tymlyTest_deletePost_1_0',
        'roleId': 'tymlyTest_teamLeader',
        'allows': [ 'create' ]
      },
      {
        'stateMachineName': '*',
        'roleId': 'tymlyTest_tymlyTestAdmin',
        'allows': [ '*' ]
      },
      {
        'stateMachineName': '*',
        'roleId': 'tymlyTest_tymlyTestReadOnly',
        'allows': [ 'get' ]
      },
      {
        'stateMachineName': 'tymlyTest_createPost_1_0',
        'roleId': '$authenticated',
        'allows': [ 'create' ]
      },
      {
        'stateMachineName': 'tymlyTest_readPost_1_0',
        'roleId': '$everyone',
        'allows': [ 'create' ]
      },
      {
        'stateMachineName': 'tymlyTest_updatePost_1_0',
        'roleId': '$owner',
        'allows': [ 'create' ]
      }
    ],
    'roles': [
      { 'roleId': 'tymlyTest_boss' },
      { 'roleId': 'tymlyTest_developer' },
      { 'roleId': 'tymlyTest_teamLeader' },
      { 'roleId': 'tymlyTest_tymlyTestAdmin' },
      { 'roleId': 'tymlyTest_tymlyTestReadOnly' }
    ]
  }
)

describe('checkRoleAuthorization', () => {
  it('$everyone can do', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        null, // userId
        null, // ownerId
        [], // roles
        'stateMachine', // resourceType
        'tymlyTest_readPost_1_0', // resourceName
        'create' // action
      )).to.equal(true)
  })

  it('authorize $authenticated user', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        'john.smith', // userId
        null, // ownerId
        [], // roles
        'stateMachine', // resourceType
        'tymlyTest_createPost_1_0', // resourceName
        'create' // action
      )).to.equal(true)
  })

  it('deny something if user is not authenticated, when they need to be', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        undefined, // userId
        null, // ownerId
        [], // roles
        'stateMachine', // resourceType
        'tymlyTest_createPost_1_0', // resourceName
        'create' // action
      )).to.equal(false)
  })

  it('authorize $owner', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        'molly', // userId
        'molly', // ownerId
        [], // roles
        'stateMachine', // resourceType
        'tymlyTest_updatePost_1_0', // resourceName
        'create' // action
      )).to.equal(true)
  })

  it('authorize directly allowed via a role', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        'john.doe', // userId
        null, // ownerId
        ['tymlyTest_developer'], // roles
        'stateMachine', // resourceType
        'tymlyTest_createPost_1_0', // resourceName
        'cancel' // action
      )).to.equal(true)
  })

  it('deny if no matching role', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        'john.doe', // userId
        null, // ownerId
        ['spaceCadet', 'IRRELEVANT!'], // roles
        'stateMachine', // resourceType
        'tymlyTest_createPost_1_0', // resourceName
        'cancel' // action
      )).to.equal(false)
  })

  it('deny if no appropriate role', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        null, // userId
        null, // ownerId
        ['tymly_developer'], // roles
        'stateMachine', // resourceType
        'tymlyTest_deletePost_1_0', // resourceName
        'create' // action
      )).to.equal(false)
  })

  it('authorize by role inheritance', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        null, // userId
        null, // ownerId
        ['tymlyTest_boss'], // roles
        'stateMachine', // resourceType
        'tymlyTest_createPost_1_0', // resourceName
        'cancel' // action
      )).to.equal(true)
  })

  it('authorize something with resource and action wildcards', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        'molly', // userId
        null, // ownerId
        ['tymlyTest_tymlyTestAdmin'], // roles
        'stateMachine', // resourceType
        'tymlyTest_purgeSite_1_0', // resourceName
        'create' // action
      )).to.equal(true)
  })

  it('authorize something with just an action wildcard', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        'molly', // userId
        null, // ownerId
        ['tymlyTest_tymlyTestReadOnly'], // roles
        'stateMachine', // resourceType
        'tymlyTest_purgeSite_1_0', // resourceName
        'get' // action
      )).to.equal(true)
  })

  it('fail to authorize if irrelevant action wildcard', function () {
    expect(
      rbacIndex.checkRoleAuthorization(
        'molly', // userId
        null, // ownerId
        ['tymlyTest_tymlyTestReadOnly'], // roles
        'stateMachine', // resourceType
        'tymlyTest_purgeSite_1_0', // resourceName
        'create' // action
      )).to.equal(false)
  })
})
