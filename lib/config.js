/*
 * Bedrock Key Module Configuration.
 *
 * Copyright (c) 2012-2017 Digital Bazaar, Inc. All rights reserved.
 */
var bedrock = require('bedrock');
var config = bedrock.config;
require('bedrock-permission');
let cc = bedrock.util.config.main.computer();

config.key = {};
// root of keys collection endpoint
config.key.basePath = '/keys';
// keys to add on startup
config.key.keys = [];

// compute the baseUri
cc('key.baseUri', () => {
  // only add the Uri...
  if(config.server) {
    return config.server.baseUri;
  }
  // FIXME: Need to set the default to something more useful.
  return 'urn:key:';
});

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
