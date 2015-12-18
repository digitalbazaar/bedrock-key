/*
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */

'use strict';

var bedrock = require('bedrock');
var config = bedrock.config;
var brKey = require('../lib/main.js');

describe('bedrock-key', function() {
  it('should validate a keypair', function(done) {
    brKey.checkKeyPair(
      config.identity.test.goodKeyPair.publicKeyPem,
      config.identity.test.goodKeyPair.privateKeyPem,
      function(err) {
        should.not.exist(err);
        done();
      });
  });
  it('should error on an invalid keypair', function(done) {
    brKey.checkKeyPair(
      config.identity.test.badKeyPair.publicKeyPem,
      config.identity.test.badKeyPair.privateKeyPem,
      function(err) {
        should.exist(err);
        err.name.should.equal('InvalidKeyPair');
        done();
      });
  });
  it('should error on an invalid public key', function(done) {
    brKey.checkKeyPair(
      config.identity.test.badPublicKey.publicKeyPem,
      config.identity.test.badPublicKey.privateKeyPem,
      function(err) {
        should.exist(err);
        err.name.should.equal('InvalidPublicKey');
        done();
      });
  });
  it('should error on an invalid private key', function(done) {
    brKey.checkKeyPair(
      config.identity.test.badPrivateKey.publicKeyPem,
      config.identity.test.badPrivateKey.privateKeyPem,
      function(err) {
        should.exist(err);
        err.name.should.equal('InvalidPrivateKey');
        done();
      });
  });
});
