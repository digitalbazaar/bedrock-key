/*
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */
/* globals it, describe, should */
/* jshint node: true */

'use strict';

var brKey = require('bedrock-key');
var mockData = require('./mock.data');

describe('bedrock-key API sub-functions', () => {
  describe('public key ids', () => {

    // Tests createPublicKeyId
    it('should create a Public Key ID given a short key name', done => {
      // var id = uuid();
      var id = 'foo';
      var key;
      var keyCompare;

      keyCompare = 'urn:key:/keys/foo';
      key = brKey.createPublicKeyId(id);
      should.exist(key);
      key.should.equal(keyCompare);
      done();
    });

  }); // describe public key ids

  describe('check key pairs', () => {
    // Tests checkKeyPair
    it('should validate a keypair', function(done) {
      brKey.checkKeyPair(
        mockData.goodKeyPair.publicKeyPem,
        mockData.goodKeyPair.privateKeyPem,
        function(err) {
          should.not.exist(err);
          done();
        });
    });

    it('should error on an invalid keypair', function(done) {
      brKey.checkKeyPair(
        mockData.badKeyPair.publicKeyPem,
        mockData.badKeyPair.privateKeyPem,
        function(err) {
          should.exist(err);
          err.name.should.equal('InvalidKeyPair');
          done();
        });
    });

    it('should error on an invalid public key', function(done) {
      brKey.checkKeyPair(
        mockData.badPublicKey.publicKeyPem,
        mockData.badPublicKey.privateKeyPem,
        function(err) {
          should.exist(err);
          err.name.should.equal('InvalidPublicKey');
          done();
        });
    });

    it('should error on an invalid private key', function(done) {
      brKey.checkKeyPair(
        mockData.badPrivateKey.publicKeyPem,
        mockData.badPrivateKey.privateKeyPem,
        function(err) {
          should.exist(err);
          err.name.should.equal('InvalidPrivateKey');
          done();
        });
    });

  }); // describe check key pairs
}); // sub-functions
