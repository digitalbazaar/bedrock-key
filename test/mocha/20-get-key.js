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

describe('bedrock-key API: getPublicKey', () => {
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

    it('should return a valid public key for an actor w/ id', done => {
      var samplePublicKey = {};
      var queryPublicKey;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            queryPublicKey, actor, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(result.privateKey);
              callback();
            });
        }]
      }, done);
    });

    it('should return a valid public key for a different actor w/ id', done => {
      var samplePublicKey = {};
      var queryPublicKey;

      var mockIdentity2 = mockData.identities.regularUser2;

      async.auto({
        insert: function(callback) {
          samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
          samplePublicKey.owner = mockIdentity2.identity.id;
          brKey.addPublicKey(null, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            queryPublicKey, actor, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(result.privateKey);
              callback();
            });
        }]
      }, done);
    });

    it('should return a valid public key for an actor w/ owner', done => {
      var samplePublicKey = {};
      var queryPublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey.owner = samplePublicKey.owner;
          queryPublicKey.publicKeyPem = samplePublicKey.publicKeyPem;
          brKey.getPublicKey(
            queryPublicKey, actor, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              callback(err, result);
            });
        }]
      }, done);
    });

    it('should return error when public key is not found', done => {
      var samplePublicKey = {};
      var queryPublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: callback => {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey.id = 'https://not-found';
          brKey.getPublicKey(queryPublicKey, actor, function(err, result) {
            should.exist(err);
            should.not.exist(result);
            err.name.should.equal('NotFound');
            callback();
          });
        }]
      }, done);
    });

    it('should properly delete and return private key', done => {
      var samplePublicKey = {};
      var queryPublicKey;
      var privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, privateKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            queryPublicKey, actor, (err, result, meta, privateResult) => {
              should.not.exist(err);
              should.exist(result);
              result.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(result.privateKey);
              should.exist(privateResult);
              privateResult.privateKeyPem.should.equal(
                privateKey.privateKeyPem);
              callback();
            });
        }]
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

    it('should return a valid public key for an actor w/ id', done => {
      var samplePublicKey = {};
      var queryPublicKey;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            queryPublicKey, actor, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(result.privateKey);
              callback();
            });
        }]
      }, done);
    });

    it('should return a valid public key for a different actor', done => {
      var samplePublicKey = {};
      var queryPublicKey;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id + 1;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            queryPublicKey, actor, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(result.privateKey);
              callback();
            });
        }]
      }, done);
    });

  }); // describe: adminUser

  describe('authenticated without permission to get keys', () => {
    var mockIdentity = mockData.identities.noPermissionUser;
    var actor;
    before(done => {
      brIdentity.get(null, mockIdentity.identity.id, (err, result) => {
        actor = result;
        done(err);
      });
    });

    it('should return public key for actor w/o permissions', done => {
      var samplePublicKey = {};
      var queryPublicKey;

      // create second identity for second public key
      var mockIdentity2 = mockData.identities.regularUser;
      var secondActor = mockIdentity2.identity;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            queryPublicKey, actor, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(result.privateKey);
              callback();
            });
        }]
      }, done);
    });

    it('should not return private key for actor w/o permissions', done => {
      var samplePublicKey = {};
      var queryPublicKey;

      // create second identity for second public key
      var mockIdentity2 = mockData.identities.regularUser;
      var secondActor = mockIdentity2.identity;
      var privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, privateKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            queryPublicKey, actor, (err, result, meta, privateResult) => {
              should.not.exist(err);
              should.exist(result);
              result.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(result.privateKey);
              should.not.exist(privateResult);
              callback();
            });
        }]
      }, done);
    });

  }); // describe: noPermissionUser

  describe('User with no authentication', () => {
    var actor = {};

    it('should return public, but no private key', done => {
      var samplePublicKey = {};
      var queryPublicKey;

      // create second identity to insert public key
      var mockIdentity = mockData.identities.regularUser;
      var secondActor = mockIdentity.identity;
      var privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, privateKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryPublicKey = {id: samplePublicKey.id};
          brKey.getPublicKey(
            queryPublicKey, actor, (err, result, meta, privateResult) => {
              should.not.exist(err);
              should.exist(result);
              result.publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
              should.not.exist(result.privateKey);
              should.not.exist(privateResult);
              callback();
            });
        }]
      }, done);
    });

  }); // describe: no authentication
}); // describe getPublicKey
