/*
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */
var bedrock = require('bedrock');
var config = bedrock.config;
require('bedrock-mongodb');
require('../lib/main.js');

bedrock.events.on('bedrock.test.configure', function() {
  // mongodb config
  config.mongodb.name = 'bedrock_idp_test';
  config.mongodb.host = 'localhost';
  config.mongodb.port = 27017;
  config.mongodb.local.collection = 'bedrock_idp_test';
  // drop all collections on initialization
  config.mongodb.dropCollections = {};
  config.mongodb.dropCollections.onInit = false;
  config.mongodb.dropCollections.collections = [];
});

bedrock.start();
