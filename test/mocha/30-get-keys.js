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

describe('bedrock-key API: getPublicKeys', () => {
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

    it('should return one key for an id, w/ actor, no options', done => {
      var samplePublicKey = {};
      var queryId;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryId = actor.id;
          brKey.getPublicKeys(
            queryId, actor, (err, result) => {
              should.not.exist(err);
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
      var samplePublicKey = {};
      var queryId;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          // create id that will not be found
          queryId = actor.id + 1;
          brKey.getPublicKeys(
            queryId, actor, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.should.have.length(0);
              callback();
            });
        }]
      }, done);
    });

    it('should return no key for an id w/ sign option and no pvt Key', done => {
      var samplePublicKey = {};
      var queryId;
      var queryOptions = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      queryOptions.capability = 'sign';
      queryId = actor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          brKey.getPublicKeys(
            queryId, actor, queryOptions, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.should.have.length(0);
              callback();
            });
        }]
      }, done);
    });

    it('should return a key for an id w sign option and privateKey', done => {
      var samplePublicKey = {};
      var queryId;
      var queryOptions = {};
      var privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;
      queryOptions.capability = 'sign';
      queryId = actor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, privateKey, callback);
        },
        test: ['insert', (results, callback) => {
          brKey.getPublicKeys(
            queryId, actor, queryOptions, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.should.have.length(1);
              result[0].publicKey.publicKeyPem.should.equal(
                samplePublicKey.publicKeyPem);
              result[0].publicKey.owner.should.equal(queryId);
              result[0].publicKey.privateKey.privateKeyPem.should.equal(
                privateKey.privateKeyPem);
              callback();
            });
        }]
      }, done);
    });

    it('should return multiple keys for id', done => {
      var samplePublicKey = {};
      var samplePublicKey2 = {};
      var queryId;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      samplePublicKey2.publicKeyPem = mockData.goodKeyPair2.publicKeyPem;
      samplePublicKey2.owner = actor.id;

      async.auto({
        insert: function(callback) {
          async.series([
            callback => brKey.addPublicKey(actor, samplePublicKey, callback),
            callback => brKey.addPublicKey(actor, samplePublicKey2, callback)
          ], callback);
        },
        test: ['insert', (results, callback) => {
          queryId = actor.id;
          brKey.getPublicKeys(
            queryId, actor, (err, result) => {
              should.not.exist(err);
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

    it('should return single key from multiple in database', done => {
      var samplePublicKey = {};
      var samplePublicKey2 = {};
      var queryId, queryId2;
      // create second identity to insert public key
      var mockIdentity2 = mockData.identities.regularUser2;
      var secondActor;
      var tr1, tr2;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      samplePublicKey2.publicKeyPem = mockData.goodKeyPair2.publicKeyPem;

      async.auto({
        setup: function(callback) {
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            samplePublicKey2.owner = secondActor.id;
            callback();
          });
        },
        insert: ['setup', function(results, callback) {
          async.series([
            callback => brKey.addPublicKey(actor, samplePublicKey, callback),
            callback => brKey.addPublicKey(
              secondActor, samplePublicKey2, callback)
          ], callback);
        }],
        get1: ['insert', (results, callback) => {
          queryId = actor.id;
          brKey.getPublicKeys(queryId, actor, callback);
        }],
        get2: ['insert', (results, callback) => {
          queryId2 = secondActor.id;
          brKey.getPublicKeys(queryId2, actor, callback);
        }],
        test: ['get2', 'get1', (results, callback) => {
          tr1 = results.get1;
          tr2 = results.get2;
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
          callback();
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

    // admin gets pubic key it inserted
    it('should return one key for an id w/ actor, no options', done => {
      var samplePublicKey = {};
      var queryId;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(actor, samplePublicKey, callback);
        },
        test: ['insert', (results, callback) => {
          queryId = actor.id;
          brKey.getPublicKeys(
            queryId, actor, (err, result) => {
              should.not.exist(err);
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

    it('should return public/pvt keys from other user in database', done => {
      var samplePublicKey1 = {};
      var samplePublicKey2 = {};
      var queryId;
      var privateKey1 = {};
      var privateKey2 = {};
      // create second identity to insert public key
      var mockIdentity1 = mockData.identities.regularUser;
      var firstActor;

      samplePublicKey1.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey2.publicKeyPem = mockData.goodKeyPair2.publicKeyPem;
      privateKey1.privateKeyPem = mockData.goodKeyPair.privateKeyPem;
      privateKey2.privateKeyPem = mockData.goodKeyPair2.privateKeyPem;

      async.auto({
        setup: function(callback) {
          brIdentity.get(null, mockIdentity1.identity.id, (err, result) => {
            firstActor = result;
            samplePublicKey1.owner = firstActor.id;
            samplePublicKey2.owner = firstActor.id;
            callback();
          });
        },
        insert: ['setup', function(results, callback) {
          async.series([
            callback => brKey.addPublicKey(
              firstActor, samplePublicKey1, privateKey1, callback),
            callback => brKey.addPublicKey(
              firstActor, samplePublicKey2, privateKey2, callback)
          ], callback);
        }],
        test: ['insert', (results, callback) => {
          queryId = firstActor.id;
          brKey.getPublicKeys(queryId, actor, (err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(2);
            result[0].publicKey.publicKeyPem.should.equal(
              samplePublicKey1.publicKeyPem);
            result[0].publicKey.owner.should.equal(firstActor.id);
            result[0].publicKey.privateKey.privateKeyPem.should.equal(
              privateKey1.privateKeyPem);
            result[1].publicKey.publicKeyPem.should.equal(
              samplePublicKey2.publicKeyPem);
            result[1].publicKey.owner.should.equal(firstActor.id);
            result[1].publicKey.privateKey.privateKeyPem.should.equal(
              privateKey2.privateKeyPem);
            callback();
          });
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

    it('should return only a public key for no-permission actor', done => {
      var samplePublicKey = {};
      var queryId;
      var privateKey = {};

      // create second identity to insert public key
      var mockIdentity2 = mockData.identities.regularUser;
      var secondActor;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        setup: function(callback) {
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            samplePublicKey.owner = secondActor.id;
            callback();
          });
        },
        insert: ['setup', function(results, callback) {
          brKey.addPublicKey(
            secondActor, samplePublicKey, privateKey, callback);
        }],
        test: ['insert', (results, callback) => {
          queryId = samplePublicKey.owner;
          brKey.getPublicKeys(
            queryId, actor, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.should.have.length(1);
              result[0].publicKey.publicKeyPem.should.equal(
                samplePublicKey.publicKeyPem);
              result[0].publicKey.owner.should.equal(queryId);
              should.not.exist(result[0].publicKey.privateKey);
              callback();
            });
        }]
      }, done);
    });

  }); // describe: noPermissionUser

  describe('User with no authentication', () => {

    it('should return only a public key for no actor or options', done => {
      var samplePublicKey = {};
      var queryId;
      var privateKey = {};

      // create second identity to insert public key
      var mockIdentity2 = mockData.identities.regularUser;
      var secondActor;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        setup: function(callback) {
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            samplePublicKey.owner = secondActor.id;
            callback();
          });
        },
        insert: ['setup', function(results, callback) {
          brKey.addPublicKey(
            secondActor, samplePublicKey, privateKey, callback);
        }],
        test: ['insert', (results, callback) => {
          queryId = samplePublicKey.owner;
          brKey.getPublicKeys(
            queryId, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.should.have.length(1);
              result[0].publicKey.publicKeyPem.should.equal(
                samplePublicKey.publicKeyPem);
              result[0].publicKey.owner.should.equal(queryId);
              should.not.exist(result[0].publicKey.privateKey);
              callback();
            });
        }]
      }, done);
    });

    it('should return no public key for no actor w/ sign option', done => {
      var samplePublicKey = {};
      var queryId;
      var queryOptions = {};
      var actor = {}; // undefined;

      // create second identity to insert public key
      var mockIdentity2 = mockData.identities.regularUser;
      var secondActor;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      queryOptions.capability = 'sign';

      async.auto({
        setup: function(callback) {
          brIdentity.get(null, mockIdentity2.identity.id, (err, result) => {
            secondActor = result;
            samplePublicKey.owner = secondActor.id;
            callback();
          });
        },
        insert: ['setup', function(results, callback) {
          brKey.addPublicKey(
            secondActor, samplePublicKey, callback);
        }],
        test: ['insert', (results, callback) => {
          queryId = samplePublicKey.owner;
          brKey.getPublicKeys(
            queryId, actor, queryOptions, (err, result) => {
              should.not.exist(err);
              should.exist(result);
              result.should.have.length(0);
              callback();
            });
        }]
      }, done);
    });

  }); // describe: no authentication
}); // describe getPublicKeys
