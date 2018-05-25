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
    it('should validate a keypair', done => {
      const {publicKeyPem, privateKeyPem} = mockData.goodKeyPair;
      const publicKey = {publicKeyPem};
      const privateKey = {privateKeyPem};
      brKey.checkKeyPair({privateKey, publicKey}, err => {
        assertNoError(err);
        done();
      });
    });

    it('should error on an invalid keypair', done => {
      const {publicKeyPem, privateKeyPem} = mockData.badKeyPair;
      const publicKey = {publicKeyPem};
      const privateKey = {privateKeyPem};
      brKey.checkKeyPair({privateKey, publicKey}, err => {
        should.exist(err);
        err.name.should.equal('InvalidKeyPair');
        done();
      });
    });

    it('should error on an invalid public key', done => {
      const {publicKeyPem, privateKeyPem} = mockData.badPublicKey;
      const publicKey = {publicKeyPem};
      const privateKey = {privateKeyPem};
      brKey.checkKeyPair({privateKey, publicKey}, err => {
        should.exist(err);
        err.name.should.equal('InvalidPublicKey');
        done();
      });
    });

    it('should error on an invalid private key', done => {
      const {publicKeyPem, privateKeyPem} = mockData.badPrivateKey;
      const publicKey = {publicKeyPem};
      const privateKey = {privateKeyPem};
      brKey.checkKeyPair({privateKey, publicKey}, err => {
        should.exist(err);
        err.name.should.equal('InvalidPrivateKey');
        done();
      });
    });

  }); // describe check key pairs
}); // sub-functions
