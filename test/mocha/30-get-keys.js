/*
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const mockData = require('./mock.data');
const brIdentity = require('bedrock-identity');
const helpers = require('./helpers');

describe('bedrock-key API: getPublicKeys', () => {
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

    it('should return one key for an id, w/ actor, no options', done => {
      const samplePublicKey = {};
      let queryId;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) => {
          queryId = keyOwner.id;
          brKey.getPublicKeys({id: queryId, actor}, (err, result) => {
            assertNoError(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              samplePublicKey.publicKeyPem);
            result[0].publicKey.owner.should.equal(queryId);
            callback();
          });
        }]
      }, done);
    });

    it('should return no key for an id with no public keys', done => {
      const samplePublicKey = {};
      let queryId;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) => {
          // create id that will not be found
          queryId = keyOwner.id + 1;
          brKey.getPublicKeys({id: queryId, actor}, (err, result) => {
            assertNoError(err);
            should.exist(result);
            result.should.have.length(0);
            callback();
          });
        }]
      }, done);
    });

    it('should return no key for an id w/ sign option and no pvt Key', done => {
      const samplePublicKey = {};
      const options = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;
      options.capability = 'sign';
      const queryId = keyOwner.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) => {
          brKey.getPublicKeys({actor, id: queryId, options}, (err, result) => {
            assertNoError(err);
            should.exist(result);
            result.should.have.length(0);
            callback();
          });
        }]
      }, done);
    });

    it('should return a key for an id w sign option and privateKey', done => {
      const samplePublicKey = {};
      const options = {};
      const samplePrivateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;
      samplePrivateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;
      options.capability = 'sign';
      const queryId = keyOwner.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: samplePublicKey, privateKey: samplePrivateKey},
          callback),
        test: ['insert', (results, callback) => brKey.getPublicKeys(
          {actor, id: queryId, options}, (err, result) => {
            assertNoError(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              samplePublicKey.publicKeyPem);
            result[0].publicKey.owner.should.equal(queryId);
            result[0].publicKey.privateKey.privateKeyPem.should.equal(
              samplePrivateKey.privateKeyPem);
            callback();
          })]
      }, done);
    });

    it('should return multiple keys for id', done => {
      const samplePublicKey = {};
      const samplePublicKey2 = {};
      let queryId;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;
      samplePublicKey2.publicKeyPem = mockData.goodKeyPair2.publicKeyPem;
      samplePublicKey2.owner = keyOwner.id;

      async.auto({
        insert: callback => {
          async.series([
            callback => brKey.addPublicKey(
              {actor, publicKey: samplePublicKey}, callback),
            callback => brKey.addPublicKey(
              {actor, publicKey: samplePublicKey2}, callback)
          ], callback);
        },
        test: ['insert', (results, callback) => {
          queryId = keyOwner.id;
          brKey.getPublicKeys({actor, id: queryId}, (err, result) => {
            assertNoError(err);
            should.exist(result);
            result.should.have.length(2);
            result[0].publicKey.publicKeyPem.should.equal(
              samplePublicKey.publicKeyPem);
            result[0].publicKey.owner.should.equal(queryId);
            result[1].publicKey.publicKeyPem.should.equal(
              samplePublicKey2.publicKeyPem);
            result[1].publicKey.owner.should.equal(queryId);
            callback();
          });
        }]
      }, done);
    });

    it('should return single key from multiple in database', async () => {
      // create second identity to insert public key
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondOwner = mockIdentity2.identity;
      const secondActor = await brIdentity.getCapabilities(
        {id: secondOwner.id});

      const samplePublicKey = {};
      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;

      const samplePublicKey2 = {};
      samplePublicKey2.publicKeyPem = mockData.goodKeyPair2.publicKeyPem;
      samplePublicKey2.owner = secondOwner.id;

      await brKey.addPublicKey(
        {actor, publicKey: samplePublicKey});
      await brKey.addPublicKey(
        {actor: secondActor, publicKey: samplePublicKey2});

      const queryId = keyOwner.id;
      const tr1 = await brKey.getPublicKeys({actor, id: queryId});

      const queryId2 = secondOwner.id;
      const tr2 = await brKey.getPublicKeys({actor, id: queryId2});

      should.exist(tr1);
      tr1.should.have.length(1);
      tr1[0].publicKey.publicKeyPem.should.equal(
        samplePublicKey.publicKeyPem);
      tr1[0].publicKey.owner.should.equal(queryId);
      should.exist(tr2);
      tr2.should.have.length(1);
      tr2[0].publicKey.publicKeyPem.should.equal(
        samplePublicKey2.publicKeyPem);
      tr2[0].publicKey.owner.should.equal(queryId2);
    });

  }); // describe regularUser

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const keyOwner = mockIdentity.identity;
    let actor;
    before(async () => {
      actor = await brIdentity.getCapabilities({id: mockIdentity.identity.id});
    });

    // admin gets pubic key it inserted
    it('should return one key for an id w/ actor, no options', done => {
      const samplePublicKey = {};
      let queryId;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) => {
          queryId = keyOwner.id;
          brKey.getPublicKeys({actor, id: queryId}, (err, result) => {
            assertNoError(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              samplePublicKey.publicKeyPem);
            result[0].publicKey.owner.should.equal(queryId);
            callback();
          });
        }]
      }, done);
    });

    it('should return public/pvt keys from other user in database',
      async () => {
      const samplePublicKey1 = {};
      const samplePublicKey2 = {};
      const privateKey1 = {};
      const privateKey2 = {};
      // create second identity to insert public key
      const mockIdentity1 = mockData.identities.regularUser;
      const firstOwner = mockIdentity1.identity;
      const firstActor = await brIdentity.getCapabilities({id: firstOwner.id});

      samplePublicKey1.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey1.owner = firstOwner.id;
      samplePublicKey2.owner = firstOwner.id;
      samplePublicKey2.publicKeyPem = mockData.goodKeyPair2.publicKeyPem;
      privateKey1.privateKeyPem = mockData.goodKeyPair.privateKeyPem;
      privateKey2.privateKeyPem = mockData.goodKeyPair2.privateKeyPem;

      await brKey.addPublicKey({
        actor: firstActor,
        publicKey: samplePublicKey1,
        privateKey: privateKey1
      });

      await brKey.addPublicKey({
        actor: firstActor,
        publicKey: samplePublicKey2,
        privateKey: privateKey2
      });

      const queryId = firstOwner.id;
      const result = await brKey.getPublicKeys({actor, id: queryId});
      should.exist(result);
      result.should.have.length(2);
      result[0].publicKey.publicKeyPem.should.equal(
        samplePublicKey1.publicKeyPem);
      result[0].publicKey.owner.should.equal(firstOwner.id);
      result[0].publicKey.privateKey.privateKeyPem.should.equal(
        privateKey1.privateKeyPem);
      result[1].publicKey.publicKeyPem.should.equal(
        samplePublicKey2.publicKeyPem);
      result[1].publicKey.owner.should.equal(firstOwner.id);
      result[1].publicKey.privateKey.privateKeyPem.should.equal(
        privateKey2.privateKeyPem);
    });

  }); // describe: adminUser

  describe('authenticated as noPermissionUser', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    let actor;
    before(async () => {
      actor = await brIdentity.getCapabilities({id: mockIdentity.identity.id});
    });

    it('should return only a public key for no-permission actor', async () => {
      // create second identity to insert public key
      const mockIdentity2 = mockData.identities.regularUser;
      const secondOwner = mockIdentity2.identity;
      const secondActor = await brIdentity.getCapabilities(
        {id: secondOwner.id});

      const samplePublicKey = {};
      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;

      const samplePrivateKey = {};
      samplePublicKey.owner = secondOwner.id;
      samplePrivateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      await brKey.addPublicKey({
        actor: secondActor,
        publicKey: samplePublicKey,
        privateKey: samplePrivateKey
      });

      const queryId = samplePublicKey.owner;
      const result = await brKey.getPublicKeys({actor, id: queryId});
      should.exist(result);
      result.should.have.length(1);
      result[0].publicKey.publicKeyPem.should.equal(
        samplePublicKey.publicKeyPem);
      result[0].publicKey.owner.should.equal(queryId);
      should.not.exist(result[0].publicKey.privateKey);
    });

  }); // describe: noPermissionUser

  describe('User with no authentication', () => {

    it('should return only a public key for no actor or options', async () => {
      // create second identity to insert public key
      const mockIdentity2 = mockData.identities.regularUser;
      const secondOwner = mockIdentity2.identity;
      const secondActor = await brIdentity.getCapabilities(
        {id: secondOwner.id});

      const samplePublicKey = {};
      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondOwner.id;

      const samplePrivateKey = {};
      samplePrivateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      await brKey.addPublicKey({
        actor: secondActor,
        publicKey: samplePublicKey,
        privateKey: samplePrivateKey
      });

      const queryId = samplePublicKey.owner;
      const result = await brKey.getPublicKeys({id: queryId});
      should.exist(result);
      result.should.have.length(1);
      result[0].publicKey.publicKeyPem.should.equal(
        samplePublicKey.publicKeyPem);
      result[0].publicKey.owner.should.equal(queryId);
      should.not.exist(result[0].publicKey.privateKey);
    });

    it('should return no public key for no actor w/ sign option', async () => {
      const actor = {}; // undefined;

      // create second identity to insert public key
      const mockIdentity2 = mockData.identities.regularUser;
      const secondOwner = mockIdentity2.identity;
      const secondActor = await brIdentity.getCapabilities(
        {id: secondOwner.id});

      const samplePublicKey = {};
      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondOwner.id;

      const options = {};
      options.capability = 'sign';

      await brKey.addPublicKey(
        {actor: secondActor, publicKey: samplePublicKey});
      const queryId = samplePublicKey.owner;
      const result = await brKey.getPublicKeys({actor, id: queryId, options});
      should.exist(result);
      result.should.have.length(0);
    });

  }); // describe: no authentication
}); // describe getPublicKeys
