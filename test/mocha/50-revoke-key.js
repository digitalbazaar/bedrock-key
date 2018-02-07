/*
 * Copyright (c) 2015-2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const mockData = require('./mock.data');
const brIdentity = require('bedrock-identity');
const helpers = require('./helpers');

describe('bedrock-key API: revokePublicKey', () => {
  before(done => {
    helpers.prepareDatabase(mockData, done);
  });
  beforeEach(function(done) {
    helpers.removeCollection('publicKey', done);
  });

  describe('authenticated as regularUser', () => {
    const mockIdentity = mockData.identities.regularUser;
    let actor;
    before(done => {
      brIdentity.get(null, mockIdentity.identity.id, (err, result) => {
        actor = result;
        done(err);
      });
    });

    it('should revoke a public key', done => {
      const originalPublicKey = {};
      let queryPublicKey;
      let revPublicKey;
      let orig;
      let final;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, callback);
        },
        readOrig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['readOrig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        readRev: ['revoke', (results, callback) => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readRev', (results, callback) => {
          orig = results.readOrig[0];
          final = results.readRev[0];
          orig.sysStatus.should.equal('active');
          final.sysStatus.should.equal('disabled');
          orig.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          should.not.exist(orig.revoked);
          should.exist(final.revoked);
          callback();
        }]
      }, done);
    });

    it('should revoke public and private key', done => {
      const originalPublicKey = {};
      const queryPublicKey = {};
      let revPublicKey;
      let orig;
      let final;
      const privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, privateKey, callback);
        },
        readOrig: ['insert', (results, callback) => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['readOrig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        readRev: ['revoke', (results, callback) => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readRev', (results, callback) => {
          orig = results.readOrig;
          final = results.readRev;
          orig[0].sysStatus.should.equal('active');
          final[0].sysStatus.should.equal('disabled');
          orig[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          should.not.exist(orig[0].revoked);
          should.exist(final[0].revoked);
          should.not.exist(orig[2].sysStatus);
          final[2].sysStatus.should.equal('disabled');
          orig[2].privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          final[2].privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          should.not.exist(orig[2].revoked);
          should.exist(final[2].revoked);
          callback();
        }]
      }, done);
    });

    it('should return an error if public key already revoked', done => {
      const originalPublicKey = {};
      let revPublicKey;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, callback);
        },
        revoke: ['insert', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        test: ['revoke', (results, callback) => {
          brKey.revokePublicKey(actor, revPublicKey, err => {
            should.exist(err);
            err.name.should.equal('NotFound');
            callback();
          });
        }]
      }, done);
    });

    it('should return an error if public key DNE', done => {
      const originalPublicKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';

      const revPublicKey = 'https://bedrock.dev:18443/keys/foo';
      brKey.revokePublicKey(actor, revPublicKey, err => {
        should.exist(err);
        err.name.should.equal('NotFound');
      });
      done();
    });

  }); // describe regularUser

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    let actor;
    before(done => {
      brIdentity.get(null, mockIdentity.identity.id, (err, result) => {
        actor = result;
        done(err);
      });
    });

    it('should revoke public and private key', done => {
      const originalPublicKey = {};
      const queryPublicKey = {};
      let revPublicKey;
      let orig;
      let final;
      const privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, privateKey, callback);
        },
        readOrig: ['insert', (results, callback) => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['readOrig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        readRev: ['revoke', (results, callback) => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readRev', (results, callback) => {
          orig = results.readOrig;
          final = results.readRev;
          orig[0].sysStatus.should.equal('active');
          final[0].sysStatus.should.equal('disabled');
          orig[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          should.not.exist(orig[0].revoked);
          should.exist(final[0].revoked);
          should.not.exist(orig[2].sysStatus);
          final[2].sysStatus.should.equal('disabled');
          orig[2].privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          final[2].privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          should.not.exist(orig[2].revoked);
          should.exist(final[2].revoked);
          callback();
        }]
      }, done);
    });

    it('should revoke public and private key for other user', done => {
      const originalPublicKey = {};
      const queryPublicKey = {};
      let revPublicKey;
      let orig;
      let final;
      const privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id + 1;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, privateKey, callback);
        },
        readOrig: ['insert', (results, callback) => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['readOrig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        readRev: ['revoke', (results, callback) => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readRev', (results, callback) => {
          orig = results.readOrig;
          final = results.readRev;
          orig[0].sysStatus.should.equal('active');
          final[0].sysStatus.should.equal('disabled');
          orig[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          should.not.exist(orig[0].revoked);
          should.exist(final[0].revoked);
          should.not.exist(orig[2].sysStatus);
          final[2].sysStatus.should.equal('disabled');
          orig[2].privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          final[2].privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          should.not.exist(orig[2].revoked);
          should.exist(final[2].revoked);
          callback();
        }]
      }, done);
    });

  }); // describe: adminUser

  describe('authenticated as noPermissionUser', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    let actor;
    before(done => {
      brIdentity.get(null, mockIdentity.identity.id, (err, result) => {
        actor = result;
        done(err);
      });
    });

    it('should return an error if actor lacks permission', done => {
      const originalPublicKey = {};
      let revPublicKey;

      // create second identity to insert public key
      const mockIdentity2 = mockData.identities.regularUser;
      let secondActor;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.label = 'Key 00';

      async.auto({
        setup: function(callback) {
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback();
          });
        },
        insert: ['setup', function(results, callback) {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(secondActor, originalPublicKey, callback);
        }],
        test: ['insert', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, err => {
            should.exist(err);
            err.name.should.equal('PermissionDenied');
            callback();
          });
        }]
      }, done);
    });

  }); // describe: noPermissionUser

  describe('User with no authentication', () => {

    const actor = {};

    // null actor will revoke; Undefined actor will cause a different error.
    it('should return error when not authenticated', done => {
      const originalPublicKey = {};
      let revPublicKey;

      // create second identity to insert public key
      const mockIdentity2 = mockData.identities.regularUser;
      let secondActor;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.label = 'Key 00';

      async.auto({
        setup: function(callback) {
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback();
          });
        },
        insert: ['setup', function(results, callback) {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(secondActor, originalPublicKey, callback);
        }],
        test: ['insert', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, err => {
            should.exist(err);
            err.name.should.equal('PermissionDenied');
            callback();
          });
        }]
      }, done);
    });

  }); // describe: no authentication
}); // describe revoke public keys
