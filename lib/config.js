/*
 * Bedrock Key Module Configuration.
 *
 * Copyright (c) 2012-2017 Digital Bazaar, Inc. All rights reserved.
 */
const bedrock = require('bedrock');
const config = bedrock.config;
const cc = bedrock.util.config.main.computer();

config.key = {};
// root of keys collection endpoint
config.key.basePath = '/keys';

config.key.cache = {};
config.key.cache.enable = false;
// prefix for cache keys
config.key.cache.prefix = 'pubkey';
// ttl in seconds
config.key.cache.ttl = 3600;

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
const permissions = config.permission.permissions;
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
