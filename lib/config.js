/*
 * Bedrock Key Module Configuration.
 *
 * Copyright (c) 2012-2016 Digital Bazaar, Inc. All rights reserved.
 */
var config = require('bedrock').config;
var path = require('path');
require('bedrock-permission');

config.key = {};
// root of keys collection endpoint
config.key.basePath = '/keys';
// keys to add on startup
config.key.keys = [];

// permissions
var permissions = config.permission.permissions;
permissions.PUBLIC_KEY_ACCESS = {
  id: 'PUBLIC_KEY_ACCESS',
  label: 'Access Public Key',
  comment: 'Required to access a Public Key.'
};
permissions.PUBLIC_KEY_CREATE = {
  id: 'PUBLIC_KEY_CREATE',
  label: 'Create Public Key',
  comment: 'Required to create a Public Key.'
};
permissions.PUBLIC_KEY_EDIT = {
  id: 'PUBLIC_KEY_EDIT',
  label: 'Edit Public Key',
  comment: 'Required to edit a Public Key.'
};
permissions.PUBLIC_KEY_REMOVE = {
  id: 'PUBLIC_KEY_REMOVE',
  label: 'Remove Public Key',
  comment: 'Required to remove a Public Key.'
};

// tests
config.mocha.tests.push(path.join(__dirname, '..', 'tests'));
