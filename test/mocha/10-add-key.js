/*
 * Copyright (c) 2015-2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brKey = require('bedrock-key');
const mockData = require('./mock.data');
const brIdentity = require('bedrock-identity');
const database = require('bedrock-mongodb');
const helpers = require('./helpers');

describe('bedrock-key API: addPublicKey', () => {
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
    describe('RSA key', () => {
      it('should add a valid public key with no private key', done => {
        const samplePublicKey = {};

        samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
        samplePublicKey.owner = actor.id;

        async.auto({
          insert: (callback) => {
            brKey.addPublicKey(actor, samplePublicKey, callback);
          },
          test: ['insert', (results, callback) => {
            database.collections.publicKey.find({
              'publicKey.owner': actor.id
            }).toArray(function(err, result) {
              assertNoError(err);
              should.exist(result);
              result[0].publicKey.publicKeyPem.should.equal(
                samplePublicKey.publicKeyPem);
              callback();
            });
          }]
        }, done);
      });
      it('should add a valid public key with matching private key', done => {
        const samplePublicKey = {};
        const privateKey = {};

        samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
        samplePublicKey.owner = actor.id;
        privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

        async.auto({
          insert: (callback) => {
            brKey.addPublicKey(actor, samplePublicKey, privateKey, callback);
          },
          test: ['insert', (results, callback) => {
            database.collections.publicKey.find({
              'publicKey.owner': actor.id
            }).toArray(function(err, result) {
              assertNoError(err);
              should.exist(result);
              result[0].publicKey.publicKeyPem.should.equal(
                samplePublicKey.publicKeyPem);
              result[0].publicKey.privateKey.privateKeyPem.should.equal(
                privateKey.privateKeyPem);
              callback();
            });
          }]
        }, done);
      });
      it('returns error if adding public key w/ bad private key', done => {
        const samplePublicKey = {};
        const PrivateKey = {};

        samplePublicKey.publicKeyPem = mockData.badKeyPair.publicKeyPem;
        samplePublicKey.owner = actor.id;
        PrivateKey.privateKeyPem = mockData.badKeyPair.privateKeyPem;

        brKey.addPublicKey(
          actor, samplePublicKey, PrivateKey, err => {
            should.exist(err);
            err.name.should.equal('InvalidKeyPair');
            done();
          });
      });
    }); // end RSA key
    describe('Ed25519 key', () => {
      it('should add a valid public key with no private key', done => {
        const {publicKeyBase58} = mockData.goodKeyPairEd25519;
        const {id: owner} = actor;
        const samplePublicKey = {publicKeyBase58, owner};

        async.auto({
          insert: (callback) => {
            brKey.addPublicKey(actor, samplePublicKey, callback);
          },
          test: ['insert', (results, callback) => {
            database.collections.publicKey.find({
              'publicKey.owner': actor.id
            }).toArray(function(err, result) {
              assertNoError(err);
              should.exist(result);
              result[0].publicKey.publicKeyBase58.should.equal(publicKeyBase58);
              callback();
            });
          }]
        }, done);
      });
      it('should add a valid public key with matching private key', done => {
        const {publicKeyBase58, privateKeyBase58} = mockData.goodKeyPairEd25519;
        const {id: owner} = actor;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        async.auto({
          insert: callback => {
            brKey.addPublicKey(
              actor, samplePublicKey, samplePrivateKey, callback);
          },
          test: ['insert', (results, callback) => {
            database.collections.publicKey.find({
              'publicKey.owner': actor.id
            }).toArray(function(err, result) {
              assertNoError(err);
              should.exist(result);
              result[0].publicKey.publicKeyBase58.should.equal(
                samplePublicKey.publicKeyBase58);
              result[0].publicKey.privateKey.privateKeyBase58.should.equal(
                privateKeyBase58);
              callback();
            });
          }]
        }, done);
      });
      it('returns error if publicKey and privateKey do not match', done => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519NonMatching;
        const {id: owner} = actor;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        brKey.addPublicKey(
          actor, samplePublicKey, samplePrivateKey, err => {
            should.exist(err);
            err.name.should.equal('InvalidKeyPair');
            err.message.should.contain('Key pair does not match');
            done();
          });
      });
      // public key contains an invalid character
      it('returns error on public key w/ invalid character', done => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519InvalidPublicKey;
        const {id: owner} = actor;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        brKey.addPublicKey(
          actor, samplePublicKey, samplePrivateKey, err => {
            should.exist(err);
            err.name.should.equal('InvalidPublicKey');
            err.cause.message.should.contain('Non-base58 character');
            done();
          });
      });
      // public key is 1 char short
      it('returns error on public key w/ incorrect length', done => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519InvalidPublicKey2;
        const {id: owner} = actor;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        brKey.addPublicKey(
          actor, samplePublicKey, samplePrivateKey, err => {
            should.exist(err);
            err.name.should.equal('InvalidPublicKey');
            err.cause.message.should.contain(
              '`publicKeyBase58` is not the correct length.');
            done();
          });
      });
      // private key contains an invalid character
      it('returns error on private key w/ invalid character', done => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519InvalidPrivateKey;
        const {id: owner} = actor;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        brKey.addPublicKey(
          actor, samplePublicKey, samplePrivateKey, err => {
            should.exist(err);
            err.name.should.equal('InvalidPrivateKey');
            err.cause.message.should.contain('Non-base58 character');
            done();
          });
      });
      // private key is 1 char short
      it('returns error on private key w/ incorrect length', done => {
        const {publicKeyBase58, privateKeyBase58} =
          mockData.badKeyPairEd25519InvalidPrivateKey2;
        const {id: owner} = actor;
        const samplePublicKey = {publicKeyBase58, owner};
        const samplePrivateKey = {privateKeyBase58};

        brKey.addPublicKey(
          actor, samplePublicKey, samplePrivateKey, err => {
            should.exist(err);
            err.name.should.equal('InvalidPrivateKey');
            err.cause.message.should.contain(
              '`privateKeyBase58` is not the correct length.');
            done();
          });
      });
    }); // end Ed25519 key

    it('should return error if owner id does not match', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id + 1;

      brKey.addPublicKey(
        actor, samplePublicKey, err => {
          should.exist(err);
          err.name.should.equal('PermissionDenied');
          err.details.sysPermission.should.equal('PUBLIC_KEY_CREATE');
          done();
        });
    });

    it('should add default publicKey fields: status, label, type', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: (callback) => {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          database.collections.publicKey.find({
            'publicKey.owner': actor.id
          }).toArray(function(err, result) {
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
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      samplePublicKey.sysStatus = 'non-default-status';
      samplePublicKey.label = 'non-default-label';
      samplePublicKey.type = 'non-default-type';
      samplePublicKey.id = 'https://non.default.id/1.1.1.1';

      async.auto({
        insert: (callback) => {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          database.collections.publicKey.find({
            'publicKey.owner': actor.id
          }).toArray(function(err, result) {
            assertNoError(err);
            should.exist(result);
            result[0].publicKey.sysStatus.should.equal(
              samplePublicKey.sysStatus);
            result[0].publicKey.label.should.equal(samplePublicKey.label);
            result[0].publicKey.type.should.equal(samplePublicKey.type);
            result[0].publicKey.id.should.equal(samplePublicKey.id);
            callback();
          });
        }]
      }, done);
    });

  }); // describe: regularUser

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    let actor;
    before(done => {
      brIdentity.get(null, mockIdentity.identity.id, (err, result) => {
        actor = result;
        done(err);
      });
    });

    it('should add a valid public key with no private key', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: (callback) => {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          database.collections.publicKey.find({
            'publicKey.owner': actor.id
          }).toArray(function(err, result) {
            assertNoError(err);
            should.exist(result);
            result[0].publicKey.publicKeyPem.should.equal(
              samplePublicKey.publicKeyPem);
            callback();
          });
        }]
      }, done);
    });

    it('should add public key for another user', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id + 1;

      async.auto({
        insert: (callback) => {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          database.collections.publicKey.find({
            'publicKey.owner': samplePublicKey.owner
          }).toArray(function(err, result) {
            assertNoError(err);
            should.exist(result);
            result[0].publicKey.publicKeyPem.should.equal(
              samplePublicKey.publicKeyPem);
            callback();
          });
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

    it('should return error when adding public key w/o permissions', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      brKey.addPublicKey(
        actor, samplePublicKey, err => {
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

      brKey.addPublicKey(
        actor, samplePublicKey, err => {
          should.exist(err);
          err.name.should.equal('PermissionDenied');
          err.details.sysPermission.should.equal('PUBLIC_KEY_CREATE');
          done();
        });
    });

  }); // describe: no authentication
}); // describe: add keys
