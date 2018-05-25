/*
 * Copyright (c) 2015-2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brKey = require('bedrock-key');
const mockData = require('./mock.data');

describe('bedrock-key API sub-functions', () => {
  describe('public key ids', () => {

    // Tests createPublicKeyId
    it('should create a Public Key ID given a short key name', done => {
      // const id = uuid();
      const id = 'foo';

      const keyCompare = 'urn:key:/keys/foo';
      const key = brKey.createPublicKeyId(id);
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
          assertNoError(err);
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
