/*
 * Copyright (c) 2016-2017 Digital Bazaar, Inc. All rights reserved.
 */
/* jshint node: true */
'use strict';

const async = require('async');
const brIdentity = require('bedrock-identity');
const database = require('bedrock-mongodb');
const uuid = require('uuid').v4;

const api = {};
module.exports = api;

api.createIdentity = userName => {
  const newIdentity = {
    id: 'did:' + uuid(),
    type: 'Identity',
    sysSlug: userName,
    label: userName,
    email: userName + '@bedrock.dev',
    sysPassword: 'password',
    sysPublic: ['label', 'url', 'description'],
    sysResourceRole: [],
    url: 'https://example.com',
    description: userName,
    sysStatus: 'active'
  };
  return newIdentity;
};

api.removeCollection = (collection, callback) => {
  const collectionNames = [collection];
  database.openCollections(collectionNames, () => {
    async.each(collectionNames, (collectionName, callback) => {
      database.collections[collectionName].remove({}, callback);
    }, err => callback(err));
  });
};

api.removeCollections = callback => {
  const collectionNames = ['identity', 'eventLog', 'publicKey'];
  database.openCollections(collectionNames, () => {
    async.each(collectionNames, (collectionName, callback) => {
      database.collections[collectionName].remove({}, callback);
    }, err => callback(err));
  });
};

api.prepareDatabase = (mockData, callback) => {
  async.series([
    callback => api.removeCollections(callback),
    callback => insertTestData(mockData, callback)
  ], callback);
};

// Insert identities and public keys used for testing into database
function insertTestData(mockData, callback) {
  async.forEachOf(mockData.identities, (identity, key, callback) =>
    brIdentity.insert(null, identity.identity, callback),
  err => {
    if(err) {
      if(!database.isDuplicateError(err)) {
        // duplicate error means test data is already loaded
        return callback(err);
      }
    }
    callback();
  }, callback);
}
