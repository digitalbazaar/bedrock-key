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

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';

      async.auto({
        insert: callback =>
          brKey.addPublicKey(actor, originalPublicKey, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['orig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        final: ['revoke', (results, callback) =>
          brKey.getPublicKey(queryPublicKey, actor, callback)],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          origPublicKey.sysStatus.should.equal('active');
          finalPublicKey.sysStatus.should.equal('disabled');
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          should.not.exist(origPublicKey.revoked);
          should.exist(finalPublicKey.revoked);
          callback();
        }]
      }, done);
    });

    it('should revoke public and private key', done => {
      const originalPublicKey = {};
      const queryPublicKey = {};
      let revPublicKey;
      const privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => {
          brKey.addPublicKey(actor, originalPublicKey, privateKey, callback);
        },
        orig: ['insert', (results, callback) => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['orig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        final: ['revoke', (results, callback) => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey, privateKey: origPrivateKey} = orig;
          const {publicKey: finalPublicKey, privateKey: finalPrivateKey} =
            final;
          origPublicKey.sysStatus.should.equal('active');
          finalPublicKey.sysStatus.should.equal('disabled');
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          should.not.exist(origPublicKey.revoked);
          should.exist(finalPublicKey.revoked);
          should.not.exist(origPrivateKey.sysStatus);
          finalPrivateKey.sysStatus.should.equal('disabled');
          origPrivateKey.privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          finalPrivateKey.privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          should.not.exist(origPrivateKey.revoked);
          should.exist(finalPrivateKey.revoked);
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
        insert: callback => {
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
      const privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => {
          brKey.addPublicKey(actor, originalPublicKey, privateKey, callback);
        },
        orig: ['insert', (results, callback) => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['orig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        final: ['revoke', (results, callback) => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey, privateKey: origPrivateKey} = orig;
          const {publicKey: finalPublicKey, privateKey: finalPrivateKey} =
            final;
          origPublicKey.sysStatus.should.equal('active');
          finalPublicKey.sysStatus.should.equal('disabled');
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          should.not.exist(origPublicKey.revoked);
          should.exist(finalPublicKey.revoked);
          should.not.exist(origPrivateKey.sysStatus);
          finalPrivateKey.sysStatus.should.equal('disabled');
          origPrivateKey.privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          finalPrivateKey.privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          should.not.exist(origPrivateKey.revoked);
          should.exist(finalPrivateKey.revoked);
          callback();
        }]
      }, done);
    });

    it('should revoke public and private key for other user', done => {
      const originalPublicKey = {};
      const queryPublicKey = {};
      let revPublicKey;
      const privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id + 1;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => {
          brKey.addPublicKey(actor, originalPublicKey, privateKey, callback);
        },
        orig: ['insert', (results, callback) => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['orig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        final: ['revoke', (results, callback) => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey, privateKey: origPrivateKey} = orig;
          const {publicKey: finalPublicKey, privateKey: finalPrivateKey} =
            final;
          origPublicKey.sysStatus.should.equal('active');
          finalPublicKey.sysStatus.should.equal('disabled');
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          should.not.exist(origPublicKey.revoked);
          should.exist(finalPublicKey.revoked);
          should.not.exist(origPrivateKey.sysStatus);
          finalPrivateKey.sysStatus.should.equal('disabled');
          origPrivateKey.privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          finalPrivateKey.privateKeyPem.should.equal(
            privateKey.privateKeyPem);
          should.not.exist(origPrivateKey.revoked);
          should.exist(finalPrivateKey.revoked);
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
        setup: callback => {
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
        setup: callback => {
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
