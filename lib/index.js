/*
 * Bedrock Key Module.
 *
 * Copyright (c) 2012-2017 Digital Bazaar, Inc. All rights reserved.
 */
const async = require('async');
const bedrock = require('bedrock');
const {config} = bedrock;
const brPermission = require('bedrock-permission');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const logger = require('./logger');
const util = require('util');
const BedrockError = bedrock.util.BedrockError;

// load config defaults
require('./config');

// module permissions
const PERMISSIONS = bedrock.config.permission.permissions;

// module API
const api = {};
module.exports = api;

// distributed key ID generator
let keyIdGenerator;

bedrock.events.on('bedrock-mongodb.ready', callback => {
  async.auto({
    openCollections: callback => database.openCollections(
      ['publicKey'], callback),
    createIndexes: ['openCollections', (results, callback) =>
      database.createIndexes([{
        // TODO: add identityGroup index?
        collection: 'publicKey',
        fields: {id: 1},
        options: {unique: true, background: false}
      }, {
        collection: 'publicKey',
        fields: {owner: 1, pem: 1},
        options: {unique: true, background: false}
      }], callback)],
    createIdGenerator: callback => database.getDistributedIdGenerator(
      'key', (err, idGenerator) => {
        if(!err) {
          keyIdGenerator = idGenerator;
        }
        callback(err);
      }),
    createKeys: ['createIndexes', 'createIdGenerator', (results, callback) =>
      // add keys, ignoring duplicate errors
      async.eachSeries(bedrock.config.key.keys, (i, callback) => {
        const publicKey = i.publicKey;
        const privateKey = i.privateKey || null;
        api.addPublicKey(null, publicKey, privateKey, err => {
          if(err && database.isDuplicateError(err)) {
            err = null;
          }
          callback(err);
        });
      }, callback)]
  }, err => callback(err));
});

/**
 * Creates a PublicKeyId based on server baseUri and a custom name.
 *
 * @param name the short Key name (slug).
 *
 * @return the PublicKey ID.
 */
api.createPublicKeyId = name => util.format(
  '%s%s/%s', config.key.baseUri, config.key.basePath, encodeURIComponent(name));

/**
 * Creates a new PublicKeyId.
 *
 * @param callback(err, id) called once the operation completes.
 */
function _generatePublicKeyId(callback) {
  keyIdGenerator.generateId((err, id) => {
    if(err) {
      return callback(err);
    }
    callback(null, api.createPublicKeyId(id));
  });
}

/**
 * Adds a new PublicKey to the Identity.
 *
 * @param actor the Identity performing the action.
 * @param publicKey the publicKey to add, with no ID yet set.
 * @param privateKey the privateKey that is paired with the publicKey,
 *          only provided if it is to be stored on the server.
 * @param callback(err, record) called once the operation completes.
 */
api.addPublicKey = (actor, publicKey, privateKey, callback) => {
  if(typeof privateKey === 'function') {
    callback = privateKey;
    privateKey = null;
  }
  async.auto({
    parse: callback => api.checkKeyPair(
      publicKey.publicKeyPem,
      privateKey ? privateKey.privateKeyPem : null,
      callback),
    checkPermission: ['parse', (results, callback) =>
      brPermission.checkPermission(
        actor, PERMISSIONS.PUBLIC_KEY_CREATE,
        {resource: publicKey, translate: 'owner'}, callback)],
    generateId: ['checkPermission', (results, callback) => {
      // id provided, skip public key ID generation
      if('id' in publicKey) {
        // FIXME: require perm to force id?
        logger.warning('adding public key with explicit id', publicKey);
        return callback(null, null);
      }

      _generatePublicKeyId((err, id) => {
        if(!err) {
          publicKey.id = id;
        }
        callback(err);
      });
    }],
    insert: ['generateId', (results, callback) => {
      // set default status
      if(!('sysStatus' in publicKey)) {
        publicKey.sysStatus = 'active';
      }

      // if no label was provided, add default label
      if(!('label' in publicKey)) {
        publicKey.label = util.format('Key %d', publicKey.id);
      }

      // if no type given add it
      if(!('type' in publicKey)) {
        publicKey.type = 'CryptographicKey';
      }

      // log prior to adding private key
      logger.debug('adding public key', publicKey);

      // add private key if given
      if(privateKey) {
        publicKey = bedrock.util.clone(publicKey);
        privateKey = bedrock.util.clone(privateKey);
        publicKey.privateKey = privateKey;
        privateKey.type = privateKey.type || publicKey.type;
        privateKey.label = privateKey.label || publicKey.label;
        privateKey.publicKey = publicKey.id;
      }

      // insert the publc key
      const now = Date.now();
      const record = {
        id: database.hash(publicKey.id),
        owner: database.hash(publicKey.owner),
        pem: database.hash(publicKey.publicKeyPem),
        meta: {
          created: now,
          updated: now
        },
        publicKey: publicKey
      };
      database.collections.publicKey.insert(
        record, database.writeOptions, (err, result) => {
          if(err) {
            return callback(err);
          }
          callback(null, result.ops[0]);
        });
    }]
  }, (err, results) => callback(err, results.insert));
};

/**
 * Retrieves an Identity's PublicKey.
 *
 * @param publicKey the PublicKey with 'id' or both 'owner' and
 *          'publicKeyPem' set.
 * @param actor the Identity performing the action (if given, an
 *          access check will be performed, which is useful to run when
 *          using any associated private key).
 * @param callback(err, publicKey, meta, privateKey) called once the
 *          operation completes.
 */
api.getPublicKey = (publicKey, actor, callback) => {
  if(typeof actor === 'function') {
    callback = actor;
    actor = undefined;
  }
  if(actor !== null) {
    actor = actor || undefined;
  }

  async.auto({
    find: callback => {
      const query = {};
      if('id' in publicKey) {
        query.id = database.hash(publicKey.id);
      } else {
        query.owner = database.hash(publicKey.owner);
        query.pem = database.hash(publicKey.publicKeyPem);
      }
      const projection = {_id: 0, meta: 1, publicKey: 1};
      database.collections.publicKey.findOne(
        query, projection, (err, record) => {
          if(err) {
            return callback(err);
          }
          // no such public key
          if(!record) {
            return callback(new BedrockError(
              'PublicKey not found.',
              'NotFound',
              {httpStatusCode: 404, key: publicKey, public: true}
            ));
          }
          callback(null, record);
        });
    },
    checkPermission: ['find', (results, callback) => {
      if(actor === undefined) {
        // no need to perform permission check
        return callback();
      }
      const {publicKey: resource} = results.find;
      brPermission.checkPermission(actor, PERMISSIONS.PUBLIC_KEY_ACCESS, {
        resource, translate: 'owner'
      }, err => {
        if(err && err.name === 'PermissionDenied') {
          return callback();
        }
        callback(err, true);
      });
    }]
  }, (err, results) => {
    if(err) {
      return callback(err);
    }
    const {meta, publicKey} = results.find;
    let privateKey = null;
    if(results.checkPermission) {
      privateKey = publicKey.privateKey || null;
    }
    delete publicKey.privateKey;
    callback(null, publicKey, meta, privateKey);
  });
};

/**
 * Retrieves an Identity's PublicKey(s).
 *
 * @param id the ID of the identity to get the PublicKeys for.
 * @param actor the Identity performing the action (if `undefined`, private
 *          keys will be removed from the results).
 * @param [options] the options to use:
 *           [capability] one or more key capabilities (e.g. 'sign'); this
 *             restricts the keys to return based on capabilities possessed
 *             option by the key or its pairing (e.g. 'sign' will only return
 *             public keys that can be used to identify a paired private key
 *             that is available for signing).
 * @param callback(err, records) called once the operation completes.
 */
api.getPublicKeys = (id, actor, options, callback) => {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  if(typeof actor === 'function') {
    callback = actor;
    actor = undefined;
  }
  options = options || {};
  async.auto({
    find: callback => {
      const query = {
        owner: database.hash(id)
      };
      if(options.capability === 'sign') {
        query['publicKey.privateKey'] = {$exists: true};
      }
      database.collections.publicKey.find(query, {}).toArray(callback);
    },
    checkPermission: ['find', (results, callback) => {
      if(actor === undefined) {
        return callback();
      }
      brPermission.checkPermission(
        actor, PERMISSIONS.PUBLIC_KEY_ACCESS,
        {resource: id}, err => {
          if(err && err.name === 'PermissionDenied') {
            return callback();
          }
          callback(err, true);
        });
    }],
    clean: ['checkPermission', (results, callback) => {
      const records = results.find;
      // remove private keys if no actor was provided or the
      // actor does not have permission to view
      if(actor === undefined || !results.checkPermission) {
        records.forEach(record => delete record.publicKey.privateKey);
      }
      callback(null, records);
    }]
  }, (err, results) => callback(err, results.clean));
};

/**
 * Updates descriptive data for a PublicKey.
 *
 * @param actor the Identity performing the action.
 * @param publicKey the publicKey to update.
 *   Note:  publicKey owner will be used for the permission check; therefore,
 *     it is the responsibility of the caller of this API to make sure that
 *     either the publicKey owner has been sanitized OR the publicKey owner
 *     is removed before the publicKey is sent to this API.
 * @param callback(err) called once the operation completes.
 */
// FIXME: sync private key label to public key label
api.updatePublicKey = (actor, publicKey, callback) => {
  async.auto({
    checkPermission: callback => brPermission.checkPermission(
      actor, PERMISSIONS.PUBLIC_KEY_EDIT, {
        resource: publicKey,
        translate: 'owner',
        get: _getPublicKeyForPermissionCheck
      }, callback),
    update: ['checkPermission', (results, callback) =>
      // exclude restricted fields
      database.collections.publicKey.update(
        {id: database.hash(publicKey.id)},
        {$set: database.buildUpdate(
          publicKey, 'publicKey', {exclude: [
            'publicKey.sysStatus', 'publicKey.publicKeyPem',
            'publicKey.owner']})},
        database.writeOptions,
        callback)],
    checkUpdate: ['update', (results, callback) => {
      if(results.update.result.n === 0) {
        return callback(new BedrockError(
          'Could not update public key. Public key not found.',
          'NotFound',
          {httpStatusCode: 404, key: publicKey, public: true}
        ));
      }
      callback();
    }]
  }, callback);
};

/**
 * Revokes a PublicKey.
 *
 * @param actor the Identity performing the action.
 * @param publicKeyId the ID of the publicKey to revoke.
 * @param callback(err, key) called once the operation completes.
 */
api.revokePublicKey = (actor, publicKeyId, callback) => async.auto({
  getPublicKey: callback => api.getPublicKey(
    {id: publicKeyId}, null, (err, publicKey, meta, privateKey) => {
      if(privateKey) {
        publicKey.privateKey = privateKey;
      }
      callback(err, publicKey);
    }),
  checkPermission: ['getPublicKey', (results, callback) =>
    brPermission.checkPermission(
      actor, PERMISSIONS.PUBLIC_KEY_REMOVE,
      {resource: results.getPublicKey, translate: 'owner'}, err =>
        callback(err, results.getPublicKey))],
  update: ['checkPermission', (results, callback) => {
    const publicKey = results.getPublicKey;
    // set status to disabled, add revocation date
    const revokedDate = bedrock.util.w3cDate();
    publicKey.sysStatus = 'disabled';
    publicKey.revoked = revokedDate;
    const update = {
      $set: {
        'publicKey.sysStatus': publicKey.sysStatus,
        'publicKey.revoked': publicKey.revoked
      }
    };
    // revoke private key as well if present
    if('privateKey' in publicKey) {
      publicKey.privateKey.sysStatus = 'disabled';
      publicKey.privateKey.revoked = revokedDate;
      update.$set['publicKey.privateKey.sysStatus'] =
        publicKey.privateKey.sysStatus;
      update.$set['publicKey.privateKey.revoked'] =
        publicKey.privateKey.revoked;
    }
    database.collections.publicKey.update({
      id: database.hash(publicKeyId), 'publicKey.sysStatus': 'active'
    }, update, database.writeOptions, callback);
  }],
  checkUpdate: ['update', (results, callback) => {
    if(results.update.result.n === 0) {
      return callback(new BedrockError(
        'Could not revoke public key. Public key not found or already ' +
        'revoked.',
        'NotFound',
        {httpStatusCode: 404, key: publicKeyId, public: true}
      ));
    }
    callback();
  }]
}, (err, results) => callback(err, results.getPublicKey));

/**
 * A helper function for `addPublicKey` that checks to ensure a public key can
 * be parsed and, if given, a private key is appropriately paired with it.
 *
 * @param publicKey the publicKey in PEM format.
 * @param [privateKey] the privateKey in PEM format.
 * @param callback(err) called once the operation completes.
 */
api.checkKeyPair = (publicKeyPem, privateKeyPem, callback) => {
  if(typeof privateKeyPem === 'function') {
    callback = privateKeyPem;
    privateKeyPem = null;
  }

  // parse keys and verify they match
  let parsedPublic = false;
  let parsedPrivate = false;
  let match = false;
  const plaintext = new Buffer('plaintext', 'utf8');
  let ciphertext;
  let decrypted;
  let err = null;

  try {
    ciphertext = crypto.publicEncrypt(publicKeyPem, plaintext);
    parsedPublic = true;
    if(privateKeyPem) {
      decrypted = crypto.privateDecrypt(privateKeyPem, ciphertext);
      parsedPrivate = true;
      match = plaintext.equals(decrypted);
    }
  } catch(ex) {
    // check for specific openssl error messages to know if key parsed but
    // decrypt failed
    // FIXME: improve this to be more generic
    // error:040A1079:rsa routines:RSA_padding_check_PKCS1_OAEP_mgf1:\
    // oaep decoding error
    // error:04065084:rsa routines:RSA_EAY_PRIVATE_DECRYPT:\
    // data too large for modulus
    if(ex.message.indexOf('040A1079') !== -1 ||
      ex.message.indexOf('04065084') !== -1) {
      parsedPrivate = true;
    }
    err = ex;
  }

  if(!parsedPublic) {
    return callback(new BedrockError(
      'Could not add public key to Identity. Invalid public key.',
      'InvalidPublicKey', {
        cause: err,
        httpStatusCode: 400,
        'public': true
      }));
  }

  if(privateKeyPem) {
    if(!parsedPrivate) {
      return callback(new BedrockError(
        'Could not add private key to Identity. Invalid private key.',
        'InvalidPrivateKey', {
          cause: err,
          httpStatusCode: 400,
          'public': true
        }));
    }
    if(!match) {
      return callback(new BedrockError(
        'Could not add key pair to Identity. Key pair does not match.',
        'InvalidKeyPair', {
          cause: err,
          httpStatusCode: 400,
          'public': true
        }));
    }
  }

  callback();
};

/**
 * Gets a PublicKey during a permission check.
 *
 * @param publicKey the PublicKey to get.
 * @param options the options to use.
 * @param callback(err, publicKey) called once the operation completes.
 */
function _getPublicKeyForPermissionCheck(publicKey, options, callback) {
  if(typeof publicKey === 'string') {
    publicKey = {id: publicKey || ''};
  }
  api.getPublicKey(publicKey, null, (err, publicKey) =>
    // only use first argument to callback
    callback(err, publicKey));
}
