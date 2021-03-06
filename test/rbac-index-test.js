/* eslint-env mocha */

const expect = require('chai').expect
const RbacIndex = require('../lib')

describe('rbac index', () => {
  it('verify simple index', () => {
    const roles = [
      {
        roleId: 'tymlyTest_tymlyTestAdmin',
        label: 'tymlyTest Admin',
        description: 'Do anything in the TymlyTest namespace'
      }
    ]
    const roleMemberships = []
    const permissions = [
      {
        stateMachineName: '*',
        roleId: 'tymlyTest_tymlyTestAdmin',
        allows: ['*']
      },
      {
        stateMachineName: 'tymlyTest_aDayInTheLife',
        roleId: '$authenticated',
        allows: ['*']
      },
      {
        stateMachineName: 'tymlyTest_generateUuid',
        roleId: '$authenticated',
        allows: ['*']
      },
      {
        stateMachineName: 'tymlyTest_runCallbackFunction',
        roleId: '$authenticated',
        allows: ['*']
      },
      {
        stateMachineName: 'tymlyTest_runFunction',
        roleId: '$authenticated',
        allows: ['*']
      },
      {
        stateMachineName: 'tymlyTest_runUnknownFunction',
        roleId: '$authenticated',
        allows: [
          '*'
        ]
      },
      {
        stateMachineName: 'tymlyTest_unavailableToAll',
        roleId: 'an-undefined-role',
        allows: [
          '*'
        ]
      }
    ]

    const rbac = new RbacIndex(
      'stateMachine',
      roles,
      roleMemberships,
      permissions
    )

    expect(rbac.index).to.be.eql(
      {
        stateMachine: {
          '*': {
            '*': ['tymlyTest_tymlyTestAdmin']
          },
          tymlyTest_aDayInTheLife: {
            '*': ['$authenticated']
          },
          tymlyTest_generateUuid: {
            '*': ['$authenticated']
          },
          tymlyTest_runCallbackFunction: {
            '*': ['$authenticated']
          },
          tymlyTest_runFunction: {
            '*': ['$authenticated']
          },
          tymlyTest_runUnknownFunction: {
            '*': ['$authenticated']
          },
          tymlyTest_unavailableToAll: {
            '*': []
          }
        }
      }
    )
    expect(rbac.inherits).to.be.eql(
      {
        tymlyTest_tymlyTestAdmin: ['tymlyTest_tymlyTestAdmin', '$everyone']
      }
    )
    expect(rbac.unknownRoles).to.be.eql(
      ['an-undefined-role']
    )
  })
  it('verify index', () => {
    const roles = [
      { roleId: 'tymlyTest_boss' },
      { roleId: 'tymlyTest_developer' },
      { roleId: 'tymlyTest_teamLeader' },
      { roleId: 'tymlyTest_tymlyTestAdmin' },
      { roleId: 'tymlyTest_tymlyTestReadOnly' }
    ]

    const roleMemberships = [
      {
        roleId: 'tymlyTest_boss',
        memberType: 'role',
        memberId: 'tymlyTest_teamLeader'
      },
      {
        roleId: 'tymlyTest_teamLeader',
        memberType: 'role',
        memberId: 'tymlyTest_developer'
      }
    ]

    const permissions = [
      {
        stateMachineName: 'tymlyTest_purgeSite_1_0',
        roleId: 'tymlyTest_boss',
        allows: ['create']
      },
      {
        stateMachineName: 'tymlyTest_deletePost_1_0',
        roleId: 'tymlyTest_boss',
        allows: ['cancel']
      },
      {
        stateMachineName: 'tymlyTest_createPost_1_0',
        roleId: 'tymlyTest_developer',
        allows: ['cancel']
      },
      {
        stateMachineName: 'tymlyTest_deletePost_1_0',
        roleId: 'tymlyTest_teamLeader',
        allows: ['create']
      },
      {
        stateMachineName: '*',
        roleId: 'tymlyTest_tymlyTestAdmin',
        allows: ['*']
      },
      {
        stateMachineName: '*',
        roleId: 'tymlyTest_tymlyTestReadOnly',
        allows: ['get']
      },
      {
        stateMachineName: 'tymlyTest_createPost_1_0',
        roleId: '$authenticated',
        allows: ['create']
      },
      {
        stateMachineName: 'tymlyTest_readPost_1_0',
        roleId: '$everyone',
        allows: ['create']
      },
      {
        stateMachineName: 'tymlyTest_updatePost_1_0',
        roleId: '$owner',
        allows: ['create']
      }
    ]

    const rbac = new RbacIndex(
      'stateMachine',
      roles,
      roleMemberships,
      permissions
    )

    expect(rbac.index).to.be.eql({
      stateMachine: {
        '*': {
          '*': ['tymlyTest_tymlyTestAdmin'],
          get: ['tymlyTest_tymlyTestReadOnly']
        },
        tymlyTest_createPost_1_0: {
          cancel: ['tymlyTest_developer', 'tymlyTest_teamLeader', 'tymlyTest_boss'],
          create: ['$authenticated']
        },
        tymlyTest_deletePost_1_0: {
          cancel: ['tymlyTest_boss'],
          create: ['tymlyTest_teamLeader', 'tymlyTest_boss']
        },
        tymlyTest_purgeSite_1_0: {
          create: ['tymlyTest_boss']
        },
        tymlyTest_readPost_1_0: {
          create: ['$everyone']
        },
        tymlyTest_updatePost_1_0: {
          create: ['$owner']
        }
      }
    })
    expect(rbac.inherits).to.be.eql({
      tymlyTest_boss: ['tymlyTest_boss', 'tymlyTest_teamLeader', 'tymlyTest_developer', '$everyone'],
      tymlyTest_developer: ['tymlyTest_developer', '$everyone'],
      tymlyTest_teamLeader: ['tymlyTest_teamLeader', 'tymlyTest_developer', '$everyone'],
      tymlyTest_tymlyTestAdmin: ['tymlyTest_tymlyTestAdmin', '$everyone'],
      tymlyTest_tymlyTestReadOnly: ['tymlyTest_tymlyTestReadOnly', '$everyone']
    })
  })
})
