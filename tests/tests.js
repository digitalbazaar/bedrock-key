/*
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */
/* globals after, afterEach, before, beforeEach, it, describe, should */
/* jshint node: true */

'use strict';

var bedrock = require('bedrock');
var config = bedrock.config;
var brKey = require('../lib');

describe('bedrock-key', function() {
  it('should validate a keypair', function(done) {
    brKey.checkKeyPair(
      config.key.test.goodKeyPair.publicKeyPem,
      config.key.test.goodKeyPair.privateKeyPem,
      function(err) {
        should.not.exist(err);
        done();
      });
  });
  it('should error on an invalid keypair', function(done) {
    brKey.checkKeyPair(
      config.key.test.badKeyPair.publicKeyPem,
      config.key.test.badKeyPair.privateKeyPem,
      function(err) {
        should.exist(err);
        err.name.should.equal('InvalidKeyPair');
        done();
      });
  });
  it('should error on an invalid public key', function(done) {
    brKey.checkKeyPair(
      config.key.test.badPublicKey.publicKeyPem,
      config.key.test.badPublicKey.privateKeyPem,
      function(err) {
        should.exist(err);
        err.name.should.equal('InvalidPublicKey');
        done();
      });
  });
  it('should error on an invalid private key', function(done) {
    brKey.checkKeyPair(
      config.key.test.badPrivateKey.publicKeyPem,
      config.key.test.badPrivateKey.privateKeyPem,
      function(err) {
        should.exist(err);
        err.name.should.equal('InvalidPrivateKey');
        done();
      });
  });
});
