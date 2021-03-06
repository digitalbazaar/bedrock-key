/*
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
/* jshint node: true */
'use strict';

const brIdentity = require('bedrock-identity');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
const uuid = require('uuid/v4');

const api = {};
module.exports = api;

api.createIdentity = userName => {
  const newIdentity = {
    id: 'did:test:' + uuid(),
    label: userName,
    email: userName + '@bedrock.dev',
    url: 'https://example.com',
    description: userName
  };
  return newIdentity;
};

api.removeCollections = async (
  collectionNames = ['identity', 'eventLog', 'publicKey']) => {
  await promisify(database.openCollections)(collectionNames);
  for(const collectionName of collectionNames) {
    await database.collections[collectionName].remove({});
  }
};

api.removeCollection =
  async collectionName => api.removeCollections([collectionName]);

api.prepareDatabase = async mockData => {
  await api.removeCollections();
  await insertTestData(mockData);
};

// Insert identities and public keys used for testing into database
async function insertTestData(mockData) {
  const records = Object.values(mockData.identities);
  for(const record of records) {
    try {
      await brIdentity.insert(
        {actor: null, identity: record.identity, meta: record.meta || {}});
    } catch(e) {
      if(e.name === 'DuplicateError') {
        // duplicate error means test data is already loaded
        continue;
      }
      throw e;
    }
  }
}
