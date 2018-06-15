/*
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const mockData = require('./mock.data');
const brIdentity = require('bedrock-identity');
const helpers = require('./helpers');

describe('bedrock-key API: revokePublicKey', () => {
  before(async () => {
    await helpers.prepareDatabase(mockData);
  });
  beforeEach(async () => {
    await helpers.removeCollection('publicKey');
  });

  describe('authenticated as regularUser', () => {
    const mockIdentity = mockData.identities.regularUser;
    const keyOwner = mockIdentity.identity;
    let actor;
    before(async () => {
      actor = await brIdentity.getCapabilities({id: mockIdentity.identity.id});
    });

    it('should revoke a public key', done => {
      const originalPublicKey = {};
      let queryPublicKey;
      let revPublicKey;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = keyOwner.id;
      originalPublicKey.label = 'Key 00';

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        revoke: ['orig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey({actor, publicKeyId: revPublicKey}, callback);
        }],
        final: ['revoke', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
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
      originalPublicKey.owner = keyOwner.id;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: originalPublicKey, privateKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        revoke: ['orig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey({actor, publicKeyId: revPublicKey}, callback);
        }],
        final: ['revoke', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
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
      originalPublicKey.owner = keyOwner.id;
      originalPublicKey.label = 'Key 00';

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: originalPublicKey}, callback),
        revoke: ['insert', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey({actor, publicKeyId: revPublicKey}, callback);
        }],
        test: ['revoke', (results, callback) => {
          brKey.revokePublicKey({actor, publicKeyId: revPublicKey}, err => {
            should.exist(err);
            err.name.should.equal('NotFoundError');
            callback();
          });
        }]
      }, done);
    });

    it('should return an error if public key DNE', done => {
      const originalPublicKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = keyOwner.id;
      originalPublicKey.label = 'Key 00';

      const revPublicKey = 'https://bedrock.dev:18443/keys/foo';
      brKey.revokePublicKey({actor, publicKeyId: revPublicKey}, err => {
        should.exist(err);
        err.name.should.equal('NotFoundError');
      });
      done();
    });

  }); // describe regularUser

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const keyOwner = mockIdentity.identity;
    let actor;
    before(async () => {
      actor = await brIdentity.getCapabilities({id: mockIdentity.identity.id});
    });

    it('should revoke public and private key', done => {
      const originalPublicKey = {};
      const queryPublicKey = {};
      let revPublicKey;
      const privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = keyOwner.id;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: originalPublicKey, privateKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        revoke: ['orig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey({actor, publicKeyId: revPublicKey}, callback);
        }],
        final: ['revoke', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
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
      originalPublicKey.owner = keyOwner.id + 1;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: originalPublicKey, privateKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        revoke: ['orig', (results, callback) => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey({actor, publicKeyId: revPublicKey}, callback);
        }],
        final: ['revoke', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
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
    before(async () => {
      actor = await brIdentity.getCapabilities({id: mockIdentity.identity.id});
    });

    it('should return an error if actor lacks permission', async () => {
      // create second identity to insert public key
      const mockIdentity2 = mockData.identities.regularUser;
      const secondOwner = mockIdentity2.identity;
      const secondActor = await brIdentity.getCapabilities(
        {id: secondOwner.id});

      const originalPublicKey = {};
      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = secondOwner.id;
      originalPublicKey.label = 'Key 00';

      await brKey.addPublicKey(
        {actor: secondActor, publicKey: originalPublicKey});

      const revPublicKey = originalPublicKey.id;

      let err;
      try {
        await brKey.revokePublicKey({actor, publicKeyId: revPublicKey});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('PermissionDenied');
    });

  }); // describe: noPermissionUser

  describe('User with no authentication', () => {

    const actor = {};

    // null actor will revoke; Undefined actor will cause a different error.
    it('should return error when not authenticated', async () => {
      // create second identity to insert public key
      const mockIdentity2 = mockData.identities.regularUser;
      const secondOwner = mockIdentity2.identity;
      const secondActor = await brIdentity.getCapabilities(
        {id: secondOwner.id});

      const originalPublicKey = {};
      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = secondOwner.id;
      originalPublicKey.label = 'Key 00';

      await brKey.addPublicKey(
        {actor: secondActor, publicKey: originalPublicKey});

      const revPublicKey = originalPublicKey.id;

      let err;
      try {
        await brKey.revokePublicKey({actor, publicKeyId: revPublicKey});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('PermissionDenied');
    });

  }); // describe: no authentication
}); // describe revoke public keys
