/*
 * Copyright (c) 2015-2017 Digital Bazaar, Inc. All rights reserved.
 */
/* globals it, describe, should, before, beforeEach */
/* jshint node: true */

'use strict';

var async = require('async');
var brKey = require('bedrock-key');
var mockData = require('./mock.data');
var brIdentity = require('bedrock-identity');
var helpers = require('./helpers');

describe('bedrock-key API: revokePublicKey', () => {
  before(done => {
    helpers.prepareDatabase(mockData, done);
  });
  beforeEach(function(done) {
    helpers.removeCollection('publicKey', done);
  });

  describe('authenticated as regularUser', () => {
    var mockIdentity = mockData.identities.regularUser;
    var actor;
    before(done => {
      brIdentity.get(null, mockIdentity.identity.id, (err, result) => {
        actor = result;
        done(err);
      });
    });

    it('should revoke a public key', done => {
      var originalPublicKey = {};
      var queryPublicKey, revPublicKey;
      var orig, final;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, callback);
        },
        readOrig: ['insert', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['readOrig', callback => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        readRev: ['revoke', callback => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readRev', (callback, results) => {
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
      var originalPublicKey = {};
      var queryPublicKey = {};
      var revPublicKey;
      var orig, final;
      var privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, privateKey, callback);
        },
        readOrig: ['insert', callback => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['readOrig', callback => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        readRev: ['revoke', callback => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readRev', (callback, results) => {
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
      var originalPublicKey = {};
      var revPublicKey;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, callback);
        },
        revoke: ['insert', callback => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        test: ['revoke', callback => {
          brKey.revokePublicKey(actor, revPublicKey, err => {
            should.exist(err);
            err.name.should.equal('NotFound');
            callback();
          });
        }]
      }, done);
    });

    it('should return an error if public key DNE', done => {
      var originalPublicKey = {};
      var revPublicKey;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';

      revPublicKey = 'https://bedrock.dev:18443/keys/foo';
      brKey.revokePublicKey(actor, revPublicKey, err => {
        should.exist(err);
        err.name.should.equal('NotFound');
      });
      done();
    });

  }); // describe regularUser

  describe('authenticated as adminUser', () => {
    var mockIdentity = mockData.identities.adminUser;
    var actor;
    before(done => {
      brIdentity.get(null, mockIdentity.identity.id, (err, result) => {
        actor = result;
        done(err);
      });
    });

    it('should revoke public and private key', done => {
      var originalPublicKey = {};
      var queryPublicKey = {};
      var revPublicKey;
      var orig, final;
      var privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, privateKey, callback);
        },
        readOrig: ['insert', callback => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['readOrig', callback => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        readRev: ['revoke', callback => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readRev', (callback, results) => {
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
      var originalPublicKey = {};
      var queryPublicKey = {};
      var revPublicKey;
      var orig, final;
      var privateKey = {};

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.owner = actor.id + 1;
      originalPublicKey.label = 'Key 00';
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, privateKey, callback);
        },
        readOrig: ['insert', callback => {
          queryPublicKey.id = originalPublicKey.id;
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        revoke: ['readOrig', callback => {
          revPublicKey = originalPublicKey.id;
          brKey.revokePublicKey(actor, revPublicKey, callback);
        }],
        readRev: ['revoke', callback => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readRev', (callback, results) => {
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
    var mockIdentity = mockData.identities.noPermissionUser;
    var actor;
    before(done => {
      brIdentity.get(null, mockIdentity.identity.id, (err, result) => {
        actor = result;
        done(err);
      });
    });

    it('should return an error if actor lacks permission', done => {
      var originalPublicKey = {};
      var revPublicKey;

      // create second identity to insert public key
      var mockIdentity2 = mockData.identities.regularUser;
      var secondActor;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.label = 'Key 00';

      async.auto({
        setup: function(callback) {
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback();
          });
        },
        insert: ['setup', function(callback) {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(secondActor, originalPublicKey, callback);
        }],
        test: ['insert', callback => {
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

    var actor = {};

    // null actor will revoke; Undefined actor will cause a different error.
    it('should return error when not authenticated', done => {
      var originalPublicKey = {};
      var revPublicKey;

      // create second identity to insert public key
      var mockIdentity2 = mockData.identities.regularUser;
      var secondActor;

      originalPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      originalPublicKey.label = 'Key 00';

      async.auto({
        setup: function(callback) {
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            callback();
          });
        },
        insert: ['setup', function(callback) {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(secondActor, originalPublicKey, callback);
        }],
        test: ['insert', callback => {
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
