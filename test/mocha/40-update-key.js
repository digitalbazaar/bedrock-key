/*
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const mockData = require('./mock.data');
const brIdentity = require('bedrock-identity');
const helpers = require('./helpers');
const brUtil = require('bedrock').util;

describe('bedrock-key API: updatePublicKey', () => {
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

    it('should update a RSA key, excluding restricted fields', done => {
      let newPublicKey = {};
      let queryPublicKey;
      const {publicKeyPem} = mockData.goodKeyPair;
      const {id: owner} = keyOwner;
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
      const {id: owner} = keyOwner;
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
      newPublicKey.owner = keyOwner.id;
      newPublicKey.label = 'Key 00';
      newPublicKey.id = 'https://bedrock.dev:18443/keys/1';

      brKey.updatePublicKey({actor, publicKey: newPublicKey}, err => {
        should.exist(err);
        err.name.should.equal('NotFoundError');
        err.message.should.equal(
          'Could not update public key. Public key not found.');
        done();
      });
    });

    it('should not update key if not key owner', async () => {
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondActor = await brIdentity.getCapabilities(
        {id: mockIdentity2.identity.id});

      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: keyOwner.id,
        label: 'Key 00'
      };

      const newPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        label: 'Key 01 Foo'
      };

      await brKey.addPublicKey({actor, publicKey: originalPublicKey});

      newPublicKey.id = originalPublicKey.id;

      // unsanitized publicKey owner should be deleted before API call
      delete newPublicKey.owner;

      let err;
      try {
        await brKey.updatePublicKey(
          {actor: secondActor, publicKey: newPublicKey});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('PermissionDenied');

      const queryPublicKey = {id: originalPublicKey.id};
      const record = await brKey.getPublicKey(
        {actor, publicKey: queryPublicKey});

      const final = record.publicKey;
      final.publicKeyPem.should.equal(originalPublicKey.publicKeyPem);
      final.label.should.equal(originalPublicKey.label);
      final.owner.should.equal(keyOwner.id);
    });

  }); // describe regularUser

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const keyOwner = mockIdentity.identity;
    let actor;
    before(async () => {
      actor = await brIdentity.getCapabilities({id: mockIdentity.identity.id});
    });

    it('should update a key, excluding restricted fields', done => {
      const originalPublicKey = {};
      let newPublicKey = {};
      let queryPublicKey;

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
          origPublicKey.owner.should.equal(keyOwner.id);
          finalPublicKey.owner.should.equal(keyOwner.id);
          origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
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
      const mockIdentity2 = mockData.identities.regularUser;
      const secondOwner = mockIdentity2.identity;
      const secondActor = await brIdentity.getCapabilities(
        {id: secondOwner.id});

      const originalPublicKey = {};
      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.label = 'Key 00';

      const newPublicKey = {};
      newPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      newPublicKey.owner = 'foo';
      newPublicKey.label = 'Key 01';

      originalPublicKey.owner = secondOwner.id;
      await brKey.addPublicKey(
        {actor: secondActor, publicKey: originalPublicKey});

      newPublicKey.id = originalPublicKey.id;

      let err;
      try {
        await brKey.updatePublicKey({actor, publicKey: newPublicKey});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('PermissionDenied');
    });

  }); // describe: noPermissionUser

  describe('User with no authentication', () => {
    const actor = {};

    it('should return error when not authenticated', async () => {
      const mockIdentity2 = mockData.identities.regularUser;
      const secondOwner = mockIdentity2.identity;
      const secondActor = await brIdentity.getCapabilities(
        {id: secondOwner.id});

      const originalPublicKey = {};
      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = secondOwner.id;
      originalPublicKey.label = 'Key 00';

      const newPublicKey = {};
      newPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      newPublicKey.owner = 'foo';
      newPublicKey.label = 'Key 01';

      await brKey.addPublicKey(
        {actor: secondActor, publicKey: originalPublicKey});

      newPublicKey.id = originalPublicKey.id;

      let err;
      try {
        await brKey.updatePublicKey({actor, publicKey: newPublicKey});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('PermissionDenied');
    });

  }); // describe: no authentication

}); // describe update public keys
