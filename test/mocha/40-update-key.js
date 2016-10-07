/*
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */
/* globals it, describe, should, before, beforeEach */
/* jshint node: true */

'use strict';

var async = require('async');
var brKey = require('bedrock-key');
var mockData = require('./mock.data');
var brIdentity = require('bedrock-identity');
var helpers = require('./helpers');
var brUtil = require('bedrock').util;

describe('bedrock-key API: updatePublicKey', () => {
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

    it('should update a key, excluding restricted fields', done => {
      var originalPublicKey = {};
      var newPublicKey = {};
      var queryPublicKey, orig, final;

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
        update: ['readOrig', (callback, results) => {
          newPublicKey = brUtil.clone(results.readOrig[0]);
          newPublicKey.label = 'Key 01';
          newPublicKey.publicKeyPem = 'bogusPublicKey';
          newPublicKey.sysStatus = 'bogusStatus';
          brKey.updatePublicKey(actor, newPublicKey, callback);
        }],
        readUpdate: ['update', callback => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readUpdate', (callback, results) => {
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
        }],
      }, done);
    });

    it('should return error if key is not found', done => {
      var newPublicKey = {};

      newPublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      newPublicKey.owner = actor.id;
      newPublicKey.label = 'Key 00';
      newPublicKey.id = 'https://bedrock.dev:18443/keys/1';

      brKey.updatePublicKey(actor, newPublicKey, (err, result) => {
        should.exist(err);
        err.name.should.equal('NotFound');
        err.message.should.equal(
          'Could not update public key. Public key not found.');
      });
      done();
    });

    it('should not update key if not key owner', done => {
      var originalPublicKey = {};
      var newPublicKey = {};
      var secondActor, queryPublicKey, final;
      var mockIdentity2 = mockData.identities.regularUser2;

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
        insert: ['setup', function(callback) {
          brKey.addPublicKey(actor, originalPublicKey, callback);
        }],
        update: ['insert', callback => {
          newPublicKey.id = originalPublicKey.id;
          // Unsanitized publicKey owner should be deleted before API call
          delete newPublicKey.owner;
          brKey.updatePublicKey(secondActor, newPublicKey, (err, result) => {
            should.exist(err);
            err.name.should.equal('PermissionDenied');
            callback();
          });
        }],
        readUpdate: ['update', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readUpdate', (callback, results) => {
          final = results.readUpdate;
          final[0].publicKeyPem.should.equal(originalPublicKey.publicKeyPem);
          final[0].label.should.equal(originalPublicKey.label);
          final[0].owner.should.equal(actor.id);
          callback();
        }],
      }, done);
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

    it('should update a key, excluding restricted fields', done => {
      var originalPublicKey = {};
      var newPublicKey = {};
      var queryPublicKey, orig, final;

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
        update: ['readOrig', (callback, results) => {
          newPublicKey = brUtil.clone(results.readOrig[0]);
          newPublicKey.label = 'Key 01';
          newPublicKey.publicKeyPem = 'bogusPublicKey';
          newPublicKey.sysStatus = 'bogusStatus';
          brKey.updatePublicKey(actor, newPublicKey, callback);
        }],
        readUpdate: ['update', callback => {
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        test: ['readUpdate', (callback, results) => {
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
        }],
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
      var newPublicKey = {};
      var secondActor;
      var mockIdentity2 = mockData.identities.regularUser;

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
        insert: ['setup', function(callback) {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(secondActor, originalPublicKey, callback);
        }],
        test: ['insert', callback => {
          newPublicKey.id = originalPublicKey.id;
          brKey.updatePublicKey(actor, newPublicKey, (err, result) => {
            should.exist(err);
            err.name.should.equal('PermissionDenied');
            callback();
          });
        }],
      }, done);
    });

  }); // describe: noPermissionUser

  describe('User with no authentication', () => {
    var actor = {};

    it('should return error when not authenticated', done => {
      var originalPublicKey = {};
      var newPublicKey = {};
      var secondActor;
      var mockIdentity2 = mockData.identities.regularUser;

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
        insert: ['setup', function(callback) {
          originalPublicKey.owner = secondActor.id;
          brKey.addPublicKey(secondActor, originalPublicKey, callback);
        }],
        test: ['insert', callback => {
          newPublicKey.id = originalPublicKey.id;
          brKey.updatePublicKey(actor, newPublicKey, (err, result) => {
            should.exist(err);
            err.name.should.equal('PermissionDenied');
            callback();
          });
        }],
      }, done);
    });

  }); // describe: no authentication

}); // describe update public keys
