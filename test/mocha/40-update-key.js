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

    it('should update a RSA key, excluding restricted fields', done => {
      let newPublicKey = {};
      let queryPublicKey;
      const {publicKeyPem} = mockData.goodKeyPair;
      const {id: owner} = actor;
      const label = 'Key 00';
      const originalPublicKey = {label, publicKeyPem, owner};

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = brUtil.clone(results.orig.publicKey);
          newPublicKey.label = 'Key 01';
          newPublicKey.publicKeyPem = 'bogusPublicKey';
          newPublicKey.sysStatus = 'bogusStatus';
          brKey.updatePublicKey({actor, publicKey: newPublicKey}, callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          origPublicKey.label.should.equal(originalPublicKey.label);
          finalPublicKey.label.should.equal(newPublicKey.label);
          origPublicKey.publicKeyPem.should.equal(publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(publicKeyPem);
          origPublicKey.owner.should.equal(owner);
          finalPublicKey.owner.should.equal(owner);
          origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
          callback();
        }]
      }, done);
    });

    it('should update an Ed25519 key, excluding restricted fields', done => {
      let newPublicKey = {};
      let queryPublicKey;
      const {publicKeyBase58} = mockData.goodKeyPairEd25519;
      const {id: owner} = actor;
      const label = 'Key 00';
      const originalPublicKey = {label, publicKeyBase58, owner};

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = brUtil.clone(results.orig.publicKey);
          newPublicKey.label = 'Key 01';
          newPublicKey.publicKeyPem = 'bogusPublicKey';
          newPublicKey.sysStatus = 'bogusStatus';
          brKey.updatePublicKey({actor, publicKey: newPublicKey}, callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          origPublicKey.label.should.equal(originalPublicKey.label);
          finalPublicKey.label.should.equal(newPublicKey.label);
          origPublicKey.publicKeyBase58.should.equal(publicKeyBase58);
          finalPublicKey.publicKeyBase58.should.equal(publicKeyBase58);
          origPublicKey.owner.should.equal(owner);
          finalPublicKey.owner.should.equal(owner);
          origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
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

      brKey.updatePublicKey({actor, publicKey: newPublicKey}, err => {
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
        setup: callback => {
          // set up second identity with permissions
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback(err, result);
          });
        },
        insert: ['setup', (results, callback) => brKey.addPublicKey(
          {actor, publicKey: originalPublicKey}, callback)],
        update: ['insert', (results, callback) => {
          newPublicKey.id = originalPublicKey.id;
          // Unsanitized publicKey owner should be deleted before API call
          delete newPublicKey.owner;
          brKey.updatePublicKey(
            {actor: secondActor, publicKey: newPublicKey}, err => {
              should.exist(err);
              err.name.should.equal('PermissionDenied');
              callback();
            });
        }],
        readUpdate: ['update', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        test: ['readUpdate', (results, callback) => {
          final = results.readUpdate.publicKey;
          final.publicKeyPem.should.equal(originalPublicKey.publicKeyPem);
          final.label.should.equal(originalPublicKey.label);
          final.owner.should.equal(actor.id);
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

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = brUtil.clone(results.orig.publicKey);
          newPublicKey.label = 'Key 01';
          newPublicKey.publicKeyPem = 'bogusPublicKey';
          newPublicKey.sysStatus = 'bogusStatus';
          brKey.updatePublicKey({actor, publicKey: newPublicKey}, callback);
        }],
        final: ['update', (results, callback) => {
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          origPublicKey.label.should.equal(originalPublicKey.label);
          finalPublicKey.label.should.equal(newPublicKey.label);
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          origPublicKey.owner.should.equal(actor.id);
          finalPublicKey.owner.should.equal(actor.id);
          origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
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
        setup: callback => {
          // set up second identity w/ permission to add key
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback(err, result);
          });
        },
        insert: ['setup', (results, callback) => {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(
            {actor: secondActor, publicKey: originalPublicKey}, callback);
        }],
        test: ['insert', (results, callback) => {
          newPublicKey.id = originalPublicKey.id;
          brKey.updatePublicKey({actor, publicKey: newPublicKey}, err => {
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
        setup: callback => {
          // set up second identity w/ permission to add key
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback(err, result);
          });
        },
        insert: ['setup', (results, callback) => {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(
            {actor: secondActor, publicKey: originalPublicKey}, callback);
        }],
        test: ['insert', (results, callback) => {
          newPublicKey.id = originalPublicKey.id;
          brKey.updatePublicKey({actor, publicKey: newPublicKey}, err => {
            should.exist(err);
            err.name.should.equal('PermissionDenied');
            callback();
          });
        }]
      }, done);
    });

  }); // describe: no authentication

}); // describe update public keys
