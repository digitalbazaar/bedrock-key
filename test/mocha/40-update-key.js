/*
 * Copyright (c) 2015-2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const mockData = require('./mock.data');
const brIdentity = require('bedrock-identity');
const helpers = require('./helpers');
const brUtil = require('bedrock').util;

describe('bedrock-key API: updatePublicKey', () => {
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

    it('should update a key, excluding restricted fields', done => {
      const originalPublicKey = {};
      let newPublicKey = {};
      let queryPublicKey;
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
        update: ['readOrig', (results, callback) => {
          newPublicKey = brUtil.clone(results.readOrig[0]);
          newPublicKey.label = 'Key 01';
          newPublicKey.publicKeyPem = 'bogusPublicKey';
          newPublicKey.sysStatus = 'bogusStatus';
          brKey.updatePublicKey(actor, newPublicKey, callback);
        }],
        readUpdate: ['update', (results, callback) => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readUpdate', (results, callback) => {
          orig = results.readOrig;
          final = results.readUpdate;
          orig[0].label.should.equal(originalPublicKey.label);
          final[0].label.should.equal(newPublicKey.label);
          orig[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          orig[0].owner.should.equal(actor.id);
          final[0].owner.should.equal(actor.id);
          orig[0].sysStatus.should.equal(final[0].sysStatus);
          callback();
        }]
      }, done);
    });

    it('should return error if key is not found', done => {
      const newPublicKey = {};

      newPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      newPublicKey.owner = actor.id;
      newPublicKey.label = 'Key 00';
      newPublicKey.id = 'https://bedrock.dev:18443/keys/1';

      brKey.updatePublicKey(actor, newPublicKey, err => {
        should.exist(err);
        err.name.should.equal('NotFound');
        err.message.should.equal(
          'Could not update public key. Public key not found.');
      });
      done();
    });

    it('should not update key if not key owner', done => {
      const originalPublicKey = {};
      const newPublicKey = {};
      let secondActor;
      let queryPublicKey;
      let final;
      const mockIdentity2 = mockData.identities.regularUser2;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';
      newPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      newPublicKey.label = 'Key 01 Foo';

      async.auto({
        setup: function(callback) {
          // set up second identity with permissions
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback(err, result);
          });
        },
        insert: ['setup', function(results, callback) {
          brKey.addPublicKey(actor, originalPublicKey, callback);
        }],
        update: ['insert', (results, callback) => {
          newPublicKey.id = originalPublicKey.id;
          // Unsanitized publicKey owner should be deleted before API call
          delete newPublicKey.owner;
          brKey.updatePublicKey(secondActor, newPublicKey, err => {
            should.exist(err);
            err.name.should.equal('PermissionDenied');
            callback();
          });
        }],
        readUpdate: ['update', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readUpdate', (results, callback) => {
          final = results.readUpdate;
          final[0].publicKeyPem.should.equal(originalPublicKey.publicKeyPem);
          final[0].label.should.equal(originalPublicKey.label);
          final[0].owner.should.equal(actor.id);
          callback();
        }]
      }, done);
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

    it('should update a key, excluding restricted fields', done => {
      const originalPublicKey = {};
      let newPublicKey = {};
      let queryPublicKey;
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
        update: ['readOrig', (results, callback) => {
          newPublicKey = brUtil.clone(results.readOrig[0]);
          newPublicKey.label = 'Key 01';
          newPublicKey.publicKeyPem = 'bogusPublicKey';
          newPublicKey.sysStatus = 'bogusStatus';
          brKey.updatePublicKey(actor, newPublicKey, callback);
        }],
        readUpdate: ['update', (results, callback) => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readUpdate', (results, callback) => {
          orig = results.readOrig;
          final = results.readUpdate;
          orig[0].label.should.equal(originalPublicKey.label);
          final[0].label.should.equal(newPublicKey.label);
          orig[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          orig[0].owner.should.equal(actor.id);
          final[0].owner.should.equal(actor.id);
          orig[0].sysStatus.should.equal(final[0].sysStatus);
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
      const newPublicKey = {};
      let secondActor;
      const mockIdentity2 = mockData.identities.regularUser;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.label = 'Key 00';
      newPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      newPublicKey.owner = 'foo';
      newPublicKey.label = 'Key 01';

      async.auto({
        setup: function(callback) {
          // set up second identity w/ permission to add key
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback(err, result);
          });
        },
        insert: ['setup', function(results, callback) {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(secondActor, originalPublicKey, callback);
        }],
        test: ['insert', (results, callback) => {
          newPublicKey.id = originalPublicKey.id;
          brKey.updatePublicKey(actor, newPublicKey, err => {
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

    it('should return error when not authenticated', done => {
      const originalPublicKey = {};
      const newPublicKey = {};
      let secondActor;
      const mockIdentity2 = mockData.identities.regularUser;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.label = 'Key 00';
      newPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      newPublicKey.owner = 'foo';
      newPublicKey.label = 'Key 01';

      async.auto({
        setup: function(callback) {
          // set up second identity w/ permission to add key
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback(err, result);
          });
        },
        insert: ['setup', function(results, callback) {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(secondActor, originalPublicKey, callback);
        }],
        test: ['insert', (results, callback) => {
          newPublicKey.id = originalPublicKey.id;
          brKey.updatePublicKey(actor, newPublicKey, err => {
            should.exist(err);
            err.name.should.equal('PermissionDenied');
            callback();
          });
        }]
      }, done);
    });

  }); // describe: no authentication

}); // describe update public keys
