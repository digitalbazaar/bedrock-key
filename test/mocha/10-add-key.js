/*
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const mockData = require('./mock.data');
const brIdentity = require('bedrock-identity');
const database = require('bedrock-mongodb');
const helpers = require('./helpers');
const uuid = require('uuid/v4');

describe('bedrock-key API: addPublicKey', () => {
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
    describe('RSA key', () => {
      it('should add a valid public key with no private key', async () => {
        const samplePublicKey = {};

        samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
        samplePublicKey.owner = keyOwner.id;

        await brKey.addPublicKey({actor, publicKey: samplePublicKey});

        const result = await database.collections.publicKey.find(
          {'publicKey.owner': keyOwner.id}).toArray();
        should.exist(result);
        result[0].publicKey.publicKeyPem.should.equal(
          samplePublicKey.publicKeyPem);
      });
      it('should add a valid public key with matching private key',
        async () => {
        const samplePublicKey = {};
        const privateKey = {};

        samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
        samplePublicKey.owner = keyOwner.id;
        privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

        await brKey.addPublicKey(
          {actor, publicKey: samplePublicKey, privateKey});
        const result = await database.collections.publicKey.find(
          {'publicKey.owner': keyOwner.id}).toArray();
        should.exist(result);
        result[0].publicKey.publicKeyPem.should.equal(
          samplePublicKey.publicKeyPem);
        result[0].publicKey.privateKey.privateKeyPem.should.equal(
          privateKey.privateKeyPem);
      });
      it('returns error if adding public key w/ bad private key', async () => {
        const samplePublicKey = {};
        const privateKey = {};

        samplePublicKey.publicKeyPem = mockData.badKeyPair.publicKeyPem;
        samplePublicKey.owner = keyOwner.id;
        privateKey.privateKeyPem = mockData.badKeyPair.privateKeyPem;

        let err;
        try {
          await brKey.addPublicKey(
            {actor, publicKey: samplePublicKey, privateKey});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        err.name.should.equal('SyntaxError');
      });
    }); // end RSA key
    describe('Ed25519 key', () => {
      it('should add a valid public key with no private key', async () => {
        const {publicKeyBase58} = mockData.goodKeyPairEd25519;
        const {id: owner} = keyOwner;
        const samplePublicKey = {publicKeyBase58, owner};

        await brKey.addPublicKey(
          {actor, publicKey: samplePublicKey});

        const result = await database.collections.publicKey.find(
          {'publicKey.owner': keyOwner.id}).toArray();
        should.exist(result);
        result[0].publicKey.publicKeyBase58.should.equal(publicKeyBase58);
      });
      it('should add a valid public key with matching private key',
        async () => {
        const {publicKeyBase58, privateKeyBase58} = mockData.goodKeyPairEd25519;
        const {id: owner} = keyOwner;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        await brKey.addPublicKey(
          {actor, publicKey: samplePublicKey, privateKey: samplePrivateKey});
        const result = await database.collections.publicKey.find(
          {'publicKey.owner': keyOwner.id}).toArray();
        should.exist(result);
        result[0].publicKey.publicKeyBase58.should.equal(
          samplePublicKey.publicKeyBase58);
        result[0].publicKey.privateKey.privateKeyBase58.should.equal(
          privateKeyBase58);
      });
      it('returns error if publicKey and privateKey do not match', async () => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519NonMatching;
        const actor = brIdentity.getCapabilities({id: keyOwner.id});
        const samplePublicKey = {publicKeyBase58, owner: keyOwner.id};
        const samplePrivateKey = {privateKeyBase58};

        let err;
        try {
          await brKey.addPublicKey(
            {actor, publicKey: samplePublicKey, privateKey: samplePrivateKey});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        err.name.should.equal('InvalidStateError');
        err.message.should.contain('Key pair does not match');
      });
      // public key contains an invalid character
      it('returns error on public key w/ invalid character', async () => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519InvalidPublicKey;
        const {id: owner} = keyOwner;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        let err;
        try {
          await brKey.addPublicKey(
            {actor, publicKey: samplePublicKey, privateKey: samplePrivateKey});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        err.name.should.equal('SyntaxError');
        err.cause.message.should.contain('Non-base58 character');
      });
      // public key is 1 char short
      it('returns error on public key w/ incorrect length', done => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519InvalidPublicKey2;
        const {id: owner} = keyOwner;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        brKey.addPublicKey(
          {actor, publicKey: samplePublicKey, privateKey: samplePrivateKey},
          err => {
            should.exist(err);
            err.name.should.equal('SyntaxError');
            err.cause.message.should.contain(
              '`publicKeyBase58` is not the correct length.');
            done();
          });
      });
      // private key contains an invalid character
      it('returns error on private key w/ invalid character', done => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519InvalidPrivateKey;
        const {id: owner} = keyOwner;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        brKey.addPublicKey(
          {actor, publicKey: samplePublicKey, privateKey: samplePrivateKey},
          err => {
            should.exist(err);
            err.name.should.equal('SyntaxError');
            err.cause.message.should.contain('Non-base58 character');
            done();
          });
      });
      // private key is 1 char short
      it('returns error on private key w/ incorrect length', done => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519InvalidPrivateKey2;
        const {id: owner} = keyOwner;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        brKey.addPublicKey(
          {actor, publicKey: samplePublicKey, privateKey: samplePrivateKey},
          err => {
            should.exist(err);
            err.name.should.equal('SyntaxError');
            err.cause.message.should.contain(
              '`privateKeyBase58` is not the correct length.');
            done();
          });
      });
    }); // end Ed25519 key

    it('should return error if owner id does not match', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id + 1;

      brKey.addPublicKey({actor, publicKey: samplePublicKey}, err => {
        should.exist(err);
        err.name.should.equal('PermissionDenied');
        err.details.sysPermission.should.equal('PUBLIC_KEY_CREATE');
        done();
      });
    });

    it('should add default publicKey fields: status, label, type', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;

      async.auto({
        insert: callback =>
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) => {
          database.collections.publicKey.find({
            'publicKey.owner': keyOwner.id
          }).toArray((err, result) => {
            assertNoError(err);
            should.exist(result);
            result[0].publicKey.sysStatus.should.equal('active');
            result[0].publicKey.label.startsWith('Key').should.be.true;
            result[0].publicKey.type.should.equal('CryptographicKey');
            callback();
          });
        }]
      }, done);
    });

    it('should add non-default status, label, type, and id', done => {
      const {publicKeyPem} = mockData.goodKeyPair;
      const {id: owner} = keyOwner;
      const samplePublicKey = {
        id: `https://non.default.id/${uuid()}`,
        label: 'non-default-label',
        owner,
        publicKeyPem,
        sysStatus: 'non-default-status',
        type: 'non-default-type'
      };

      async.auto({
        insert: callback =>
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) =>
          database.collections.publicKey.find({
            'publicKey.owner': keyOwner.id
          }).toArray((err, result) => {
            assertNoError(err);
            should.exist(result);
            result[0].publicKey.sysStatus.should.equal(
              samplePublicKey.sysStatus);
            result[0].publicKey.label.should.equal(samplePublicKey.label);
            result[0].publicKey.type.should.equal(samplePublicKey.type);
            result[0].publicKey.id.should.equal(samplePublicKey.id);
            callback();
          })]
      }, done);
    });

    it('return DuplicateError on key with a duplicate `id`', done => {
      const {publicKeyPem} = mockData.goodKeyPair;
      const {id: owner} = keyOwner;
      const samplePublicKey = {
        id: `https://non.default.id/${uuid()}`,
        owner,
        publicKeyPem,
      };

      async.auto({
        insert: callback =>
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, callback),
        insertAgain: ['insert', (results, callback) =>
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, err => {
            should.exist(err);
            err.name.should.equal('DuplicateError');
            should.exist(err.details.keyId);
            err.details.keyId.should.equal(samplePublicKey.id);
            callback();
          })],
      }, done);
    });

  }); // describe: regularUser

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const keyOwner = mockIdentity.identity;
    let actor;
    before(async () => {
      actor = await brIdentity.getCapabilities({id: mockIdentity.identity.id});
    });

    it('should add a valid public key with no private key', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;

      async.auto({
        insert: callback =>
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) =>
          database.collections.publicKey.find({
            'publicKey.owner': keyOwner.id
          }).toArray((err, result) => {
            assertNoError(err);
            should.exist(result);
            result[0].publicKey.publicKeyPem.should.equal(
              samplePublicKey.publicKeyPem);
            callback();
          })]
      }, done);
    });

    it('should add public key for another user', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id + 1;

      async.auto({
        insert: callback =>
          brKey.addPublicKey({actor, publicKey: samplePublicKey}, callback),
        test: ['insert', (results, callback) =>
          database.collections.publicKey.find({
            'publicKey.owner': samplePublicKey.owner
          }).toArray((err, result) => {
            assertNoError(err);
            should.exist(result);
            result[0].publicKey.publicKeyPem.should.equal(
              samplePublicKey.publicKeyPem);
            callback();
          })]
      }, done);
    });

  }); // describe: adminUser

  describe('authenticated as noPermissionUser', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    const keyOwner = mockIdentity.identity;
    let actor;
    before(async () => {
      actor = await brIdentity.getCapabilities({id: mockIdentity.identity.id});
    });

    it('should return error when adding public key w/o permissions', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;

      brKey.addPublicKey({actor, publicKey: samplePublicKey}, err => {
        should.exist(err);
        err.name.should.equal('PermissionDenied');
        err.details.sysPermission.should.equal('PUBLIC_KEY_CREATE');
        done();
      });
    });

  }); // describe: noPermissionUser

  describe('user with no authentication', () => {

    const actor = {};

    it('should return error when not authenticated', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = 'owner';

      brKey.addPublicKey({actor, publicKey: samplePublicKey}, err => {
        should.exist(err);
        err.name.should.equal('PermissionDenied');
        err.details.sysPermission.should.equal('PUBLIC_KEY_CREATE');
        done();
      });
    });

  }); // describe: no authentication
}); // describe: add keys
