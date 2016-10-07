/*
 * Bedrock Key Module Test Configuration.
 *
 * Copyright (c) 2012-2016 Digital Bazaar, Inc. All rights reserved.
 */
var bedrock = require('bedrock');
var config = bedrock.config;
var path = require('path');

var permissions = config.permission.permissions;
var roles = config.permission.roles;

config.mocha.tests.push(path.join(__dirname, 'mocha'));

// bedrock.events.on('bedrock.test.configure', function() {
  // mongodb config
config.mongodb.name = 'bedrock_key_test';
config.mongodb.host = 'localhost';
config.mongodb.port = 27017;
config.mongodb.local.collection = 'bedrock_key_test';
config.mongodb.username = 'bedrock';
config.mongodb.password = 'password';
config.mongodb.adminPrompt = true;
// drop all collections on initialization
config.mongodb.dropCollections = {};
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];
// });

roles['bedrock-key.test'] = {
  id: 'bedrock-key.test',
  label: 'Key Test Role',
  comment: 'Role for Test User',
  sysPermission: [
    permissions.PUBLIC_KEY_REMOVE.id,
    permissions.PUBLIC_KEY_ACCESS.id,
    permissions.PUBLIC_KEY_CREATE.id,
    permissions.PUBLIC_KEY_EDIT.id
  ]
};
