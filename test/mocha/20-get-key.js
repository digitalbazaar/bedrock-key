/*
 * Copyright (c) 2015-2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const mockData = require('./mock.data');
const brIdentity = require('bedrock-identity');
const helpers = require('./helpers');

describe('bedrock-key API: getPublicKey', () => {
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

    it('should return a valid public key for an actor w/ id', done => {
      const samplePublicKey = {};
      let queryPublicKey;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: callback => {
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              result.should.be.an('object');
              const {publicKey} = result;
              publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(publicKey.privateKey);
              callback();
            });
        }]
      }, done);
    });
    it('should return a valid Ed25519 public key for an actor w/ id', done => {
      const {publicKeyBase58} = mockData.goodKeyPairEd25519;
      const {id: owner} = actor;
      const samplePublicKey = {publicKeyBase58, owner};

      async.auto({
        insert: callback => {
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, callback);
        },
        test: ['insert', (results, callback) => {
          const queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              result.should.be.an('object');
              const {publicKey} = result;
              publicKey.publicKeyBase58.should.equal(publicKeyBase58);
              should.not.exist(publicKey.privateKey);
              callback();
            });
        }]
      }, done);
    });

    it('should return a valid public key for a different actor w/ id', done => {
      const samplePublicKey = {};
      let queryPublicKey;

      const mockIdentity2 = mockData.identities.regularUser2;

      async.auto({
        insert: callback => {
          samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
          samplePublicKey.owner = mockIdentity2.identity.id;
          brKey.addPublicKey(
            {actor: null, publicKey: samplePublicKey}, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              const {publicKey} = result;
              publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(publicKey.privateKey);
              callback();
            });
        }]
      }, done);
    });

    it('should return a valid public key for an actor w/ owner', done => {
      const samplePublicKey = {};
      const queryPublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: callback => {
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey.owner = samplePublicKey.owner;
          queryPublicKey.publicKeyPem = samplePublicKey.publicKeyPem;
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              const {publicKey} = result;
              publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              callback(err, result);
            });
        }]
      }, done);
    });

    it('should return error when public key is not found', done => {
      const samplePublicKey = {};
      const queryPublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: callback => {
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey.id = 'https://not-found';
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              should.exist(err);
              should.not.exist(result);
              err.name.should.equal('NotFound');
              callback();
            });
        }]
      }, done);
    });

    it('should properly return a RSA private key', done => {
      const {publicKeyPem, privateKeyPem} = mockData.goodKeyPair;
      const samplePublicKey = {publicKeyPem};
      const samplePrivateKey = {privateKeyPem};
      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: samplePublicKey, privateKey: samplePrivateKey},
          callback),
        test: ['insert', (results, callback) => {
          const queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              const {publicKey, privateKey} = result;
              publicKey.publicKeyPem.should.equal(publicKeyPem);
              should.not.exist(publicKey.privateKey);
              should.exist(privateKey);
              privateKey.privateKeyPem.should.equal(privateKeyPem);
              callback();
            });
        }]
      }, done);
    });

    it('should properly return a Ed25519 private key', done => {
      const {publicKeyBase58, privateKeyBase58} = mockData.goodKeyPairEd25519;
      const {id: owner} = actor;
      const samplePublicKey = {owner, publicKeyBase58};
      const samplePrivateKey = {privateKeyBase58};

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: samplePublicKey, privateKey: samplePrivateKey},
          callback),
        test: ['insert', (results, callback) => {
          const queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              const {publicKey, privateKey} = result;
              publicKey.publicKeyBase58.should.equal(publicKeyBase58);
              should.not.exist(publicKey.privateKey);
              should.exist(privateKey);
              privateKey.privateKeyBase58.should.equal(privateKeyBase58);
              callback();
            });
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

    it('should return a valid public key for an actor w/ id', done => {
      const samplePublicKey = {};
      let queryPublicKey;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              result.should.be.an('object');
              const {publicKey} = result;
              publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(publicKey.privateKey);
              callback();
            });
        }]
      }, done);
    });

    it('should return a valid public key for a different actor', done => {
      const samplePublicKey = {};
      let queryPublicKey;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id + 1;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              result.should.be.an('object');
              const {publicKey} = result;
              publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(publicKey.privateKey);
              callback();
            });
        }]
      }, done);
    });

  }); // describe: adminUser

  describe('authenticated without permission to get keys', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    let actor;
    before(done => {
      brIdentity.get(null, mockIdentity.identity.id, (err, result) => {
        actor = result;
        done(err);
      });
    });

    it('should return public key for actor w/o permissions', done => {
      const samplePublicKey = {};
      let queryPublicKey;

      // create second identity for second public key
      const mockIdentity2 = mockData.identities.regularUser;
      const secondActor = mockIdentity2.identity;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              result.should.be.an('object');
              const {publicKey} = result;
              publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(publicKey.privateKey);
              callback();
            });
        }]
      }, done);
    });

    it('should not return private key for actor w/o permissions', done => {
      const samplePublicKey = {};
      let queryPublicKey;

      // create second identity for second public key
      const mockIdentity2 = mockData.identities.regularUser;
      const secondActor = mockIdentity2.identity;
      const samplePrivateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;
      samplePrivateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey({
          actor: null, publicKey: samplePublicKey, privateKey: samplePrivateKey
        }, callback),
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              result.should.be.an('object');
              const {publicKey, privateKey} = result;
              publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(publicKey.privateKey);
              should.not.exist(privateKey);
              callback();
            });
        }]
      }, done);
    });

  }); // describe: noPermissionUser

  describe('User with no authentication', () => {
    const actor = {};

    it('should return public, but no private key', done => {
      const samplePublicKey = {};
      let queryPublicKey;

      // create second identity to insert public key
      const mockIdentity = mockData.identities.regularUser;
      const secondActor = mockIdentity.identity;
      const samplePrivateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;
      samplePrivateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey({
          actor: null, publicKey: samplePublicKey, privateKey: samplePrivateKey
        }, callback),
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            {actor, publicKey: queryPublicKey}, (err, result) => {
              assertNoError(err);
              should.exist(result);
              result.should.be.an('object');
              const {publicKey, privateKey} = result;
              publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(publicKey.privateKey);
              should.not.exist(privateKey);
              callback();
            });
        }]
      }, done);
    });

  }); // describe: no authentication

  describe('No actor specified.', () => {
    it('should return public, but no private key', done => {
      const samplePublicKey = {};
      let queryPublicKey;

      // create second identity to insert public key
      const mockIdentity = mockData.identities.regularUser;
      const secondActor = mockIdentity.identity;
      const samplePrivateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;
      samplePrivateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey({
          actor: null, publicKey: samplePublicKey, privateKey: samplePrivateKey
        }, callback),
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey({publicKey: queryPublicKey}, (err, result) => {
            assertNoError(err);
            should.exist(result);
            result.should.be.an('object');
            const {publicKey, privateKey} = result;
            publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
            should.not.exist(publicKey.privateKey);
            should.not.exist(privateKey);
            callback();
          });
        }],
        // second test should pass with/without cache enabled
        test2: ['test', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey({publicKey: queryPublicKey}, (err, result) => {
            assertNoError(err);
            should.exist(result);
            result.should.be.an('object');
            const {publicKey, privateKey} = result;
            publicKey.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
            should.not.exist(publicKey.privateKey);
            should.not.exist(privateKey);
            callback();
          });
        }]
      }, done);
    });

  }); // describe: no actor
}); // describe getPublicKey
