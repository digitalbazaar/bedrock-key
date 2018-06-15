/*
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
const assert = require('assert-plus');
const async = require('async');
const bedrock = require('bedrock');
const {config} = bedrock;
const brPermission = require('bedrock-permission');
const bs58 = require('bs58');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const logger = require('./logger');
const signatureAlgorithms = require('signature-algorithms');
const util = require('util');
const {promisify} = util;
const {BedrockError, callbackify: brCallbackify} = bedrock.util;

// load config defaults
require('./config');

let cache;
const {enable: cacheEnabled} = config.key.cache;
if(cacheEnabled) {
  cache = require('bedrock-redis');
}

// module permissions
const PERMISSIONS = bedrock.config.permission.permissions;

// module API
const api = {};
module.exports = api;

// distributed key ID generator
let keyIdGenerator;

// FIXME: temporary wrapper until implementation is redone w/promises
const WRAP = callbackFn => {
  return brCallbackify(promisify(callbackFn));
};

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
        options: {
          background: false,
          partialFilterExpression: {pem: {$exists: true}},
        }
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
 * Adds a new PublicKey to the Identity. Mutates `publicKey` by adding `id`
 * if an id is generated
 *
 * @param actor the Identity performing the action.
 * @param publicKey the publicKey to add, with no ID yet set.
 * @param [privateKey] the privateKey that is paired with the publicKey,
 *          only provided if it is to be stored on the server.
 * @param callback(err, record) called once the operation completes.
 */
api.addPublicKey = WRAP(({actor, privateKey = null, publicKey}, callback) => {
  assert.optionalObject(actor, 'actor');
  assert.optionalObject(privateKey, 'privateKey');
  assert.object(publicKey, 'publicKey');
  async.auto({
    parse: callback => api.checkKeyPair({privateKey, publicKey}, callback),
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
        publicKey.label = util.format('Key %d', Date.now());
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
        meta: {
          created: now,
          updated: now
        },
        publicKey: publicKey
      };
      if(publicKey.publicKeyPem) {
        record.pem = database.hash(publicKey.publicKeyPem);
      }
      database.collections.publicKey.insert(
        record, database.writeOptions, (err, result) => {
          if(err) {
            if(database.isDuplicateError(err)) {
              const {id: keyId} = record.publicKey;
              return callback(new BedrockError(
                'A key with the same `id` already exists.',
                'DuplicateError', {keyId}, err));
            }
            return callback(err);
          }
          callback(null, result.ops[0]);
        });
    }]
  }, (err, results) => callback(err, results.insert));
});

/**
 * Retrieves an Identity's PublicKey.
 *
 * @param publicKey the PublicKey with 'id' or both 'owner' and
 *          'publicKeyPem' set.
 * @param actor the Identity performing the action (if given, an
 *          access check will be performed, which is useful to run when
 *          using any associated private key).
 * @param callback(err, {publicKey, meta, privateKey}) called once the
 *          operation completes.
 */
api.getPublicKey = WRAP(({actor, publicKey}, callback) => {
  assert.optionalObject(actor);
  assert.object(publicKey, 'publicKey');

  const {id: publicKeyId, owner, publicKeyPem} = publicKey;
  // if `id` is not provided, both `owner` and `publicKeyPem` must be provided
  if(!publicKeyId) {
    assert.string(owner, 'owner');
    assert.string(publicKeyPem, 'publicKeyPem');
  }

  let cacheKey;
  if(cacheEnabled && publicKeyId) {
    cacheKey = _cacheKey(publicKeyId);
  }
  async.auto({
    cache: callback => {
      // cache is only used when dealing exclusively with public keys
      if(!(cacheEnabled && actor === undefined && cacheKey)) {
        return callback();
      }
      cache.client.get(cacheKey, (err, result) => {
        if(err) {
          return callback(err);
        }
        let publicKey;
        try {
          publicKey = JSON.parse(result);
        } catch(err) {
          return callback(err);
        }
        callback(null, publicKey);
      });
    },
    find: ['cache', (results, callback) => {
      if(results.cache) {
        return callback(null, results.cache);
      }
      const query = {};
      if(publicKeyId) {
        query.id = database.hash(publicKeyId);
      } else {
        query.owner = database.hash(owner);
        query.pem = database.hash(publicKeyPem);
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
              'NotFoundError',
              {httpStatusCode: 404, key: publicKey, public: true}
            ));
          }
          callback(null, record);
        });
    }],
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
    }],
    cacheInsert: ['find', (results, callback) => {
      // only interact with cache for unauthenticated operations, this
      // prevents the key from getting cached during revokePublicKey etc.
      if(!(cacheEnabled && !results.cache && cacheKey && actor === undefined)) {
        return callback();
      }
      const record = bedrock.util.clone(results.find);
      // never cache private keys
      delete record.publicKey.privateKey;
      const {ttl} = config.key.cache;
      cache.client.set(cacheKey, JSON.stringify(record), 'EX', ttl, callback);
    }]
  }, (err, results) => {
    if(err) {
      return callback(err);
    }
    const {meta, publicKey} = results.find;
    let privateKey = null;
    // this never happens when cacheEnabled
    if(results.checkPermission) {
      privateKey = publicKey.privateKey || null;
    }
    delete publicKey.privateKey;
    callback(null, {publicKey, meta, privateKey});
  });
});

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
api.getPublicKeys = WRAP(({id, actor, options = {}}, callback) => {
  assert.string(id);
  assert.optionalObject(actor, 'actor');
  assert.object(options, 'options');
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
});

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
api.updatePublicKey = WRAP(({actor, publicKey}, callback) => {
  assert.optionalObject(actor, 'actor');
  assert.object(publicKey, 'publicKey');
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
            'publicKey.publicKeyBase58', 'publicKey.owner']})},
        database.writeOptions,
        callback)],
    checkUpdate: ['update', (results, callback) => {
      if(results.update.result.n === 0) {
        return callback(new BedrockError(
          'Could not update public key. Public key not found.',
          'NotFoundError',
          {httpStatusCode: 404, key: publicKey, public: true}
        ));
      }
      callback();
    }],
    cacheEvict: ['checkUpdate', (results, callback) => {
      if(!cacheEnabled) {
        return callback();
      }
      cache.client.del(_cacheKey(publicKey.id), callback);
    }],
  }, callback);
});

/**
 * Revokes a PublicKey.
 *
 * @param actor the Identity performing the action.
 * @param publicKeyId the ID of the publicKey to revoke.
 * @param callback(err, key) called once the operation completes.
 */
api.revokePublicKey = WRAP(({actor, publicKeyId}, callback) => {
  if(actor === undefined) {
    return callback(new BedrockError(
      'Permission denied; no actor specified.',
      'NotAllowedError',
      {httpStatusCode: 401, publicKeyId, public: true}
    ));
  }
  assert.object(actor, 'actor');
  assert.string(publicKeyId, 'publicKeyId');
  async.auto({
    // null actor here means the cache will be bypassed
    getPublicKey: callback => api.getPublicKey(
      {actor: null, publicKey: {id: publicKeyId}}, (err, result) => {
        if(err) {
          return callback(err);
        }
        const {publicKey, privateKey} = result;
        if(privateKey) {
          publicKey.privateKey = privateKey;
        }
        callback(null, publicKey);
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
          'NotFoundError',
          {httpStatusCode: 404, key: publicKeyId, public: true}
        ));
      }
      callback();
    }],
    cacheEvict: ['checkUpdate', (results, callback) => {
      if(!cacheEnabled) {
        return callback();
      }
      cache.client.del(_cacheKey(publicKeyId), callback);
    }],
  }, (err, results) => callback(err, results.getPublicKey));
});

/**
 * A helper function for `addPublicKey` that checks to ensure a public key
 * can be parsed and, if given, a private key is appropriately paired with it.
 *
 * @param publicKey the publicKey.
 * @param [privateKey] the privateKey.
 * @param callback(err) called once the operation completes.
 */
api.checkKeyPair = WRAP(({publicKey, privateKey}, callback) => {
  assert.object(publicKey, 'publicKey');
  assert.optionalObject(privateKey, 'privateKey');
  if(publicKey.publicKeyPem) {
    return _checkKeyPairRsa({privateKey, publicKey}, callback);
  }
  if(publicKey.publicKeyBase58) {
    return _checkKeyPairEd25519({privateKey, publicKey}, callback);
  }
  callback(new BedrockError(
    '`publicKey` must include one of: publicKeyBase58, publicKeyPem.',
    'NotSupportedError', {httpStatusCode: 400, key: publicKey, public: true}
  ));
});

function _checkKeyPairEd25519({publicKey, privateKey = null}, callback) {
  const {publicKeyBase58} = publicKey;

  // validate the public key material
  try {
    assert.string(publicKeyBase58, 'publicKeyBase58');
    assert.equal(
      publicKeyBase58.length, 44,
      '`publicKeyBase58` is not the correct length.');
    // throws if there is an invalid character
    bs58.decode(publicKeyBase58);
  } catch(err) {
    return callback(new BedrockError(
      'Could not add public key to Identity. Invalid public key.',
      'SyntaxError', {
        httpStatusCode: 400,
        public: true
      }, err));
  }
  if(!privateKey) {
    return callback();
  }

  const {privateKeyBase58} = privateKey;
  // validate the private key material
  try {
    assert.string(privateKeyBase58, 'privateKeyBase58');
    assert.equal(
      privateKeyBase58.length, 88,
      '`privateKeyBase58` is not the correct length.');
    // throws if there is an invalid character
    bs58.decode(privateKeyBase58);
  } catch(err) {
    return callback(new BedrockError(
      'Could not add public key to Identity. Invalid private key.',
      'SyntaxError', {
        httpStatusCode: 400,
        public: true
      }, err));
  }

  // perform sign/verify to ensure that public and private keys match
  const plaintext = 'sign this';
  const algorithm = 'ed25519';
  async.auto({
    sign: callback => signatureAlgorithms.sign(
      {algorithm, plaintext, privateKeyBase58}, callback),
    verify: ['sign', (results, callback) => signatureAlgorithms.verify(
      {algorithm, plaintext, publicKeyBase58, signature: results.sign},
      callback)]
  }, (err, results) => {
    if(err || !results.verify) {
      return callback(new BedrockError(
        'Could not add key pair to Identity. Key pair does not match.',
        'InvalidStateError', {
          httpStatusCode: 400,
          public: true
        }, err));
    }
    callback();
  });
}

function _cacheKey(publicKeyId) {
  const {prefix} = config.key.cache;
  const idHash = database.hash(publicKeyId);
  return `${prefix}|${idHash}`;
}

function _checkKeyPairRsa({privateKey, publicKey}, callback) {
  let privateKeyPem = null;
  const {publicKeyPem} = publicKey;
  if(privateKey) {
    privateKeyPem = privateKey.privateKeyPem;
  }
  assert.string(publicKeyPem, 'publicKeyPem');
  assert.optionalString(privateKeyPem, 'privateKeyPem');
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
      'SyntaxError', {
        httpStatusCode: 400,
        public: true
      }, err));
  }

  if(privateKeyPem) {
    if(!parsedPrivate) {
      return callback(new BedrockError(
        'Could not add private key to Identity. Invalid private key.',
        'SyntaxError', {
          httpStatusCode: 400,
          public: true
        }, err));
    }
    if(!match) {
      return callback(new BedrockError(
        'Could not add key pair to Identity. Key pair does not match.',
        'SyntaxError', {
          httpStatusCode: 400,
          public: true
        }, err));
    }
  }

  callback();
}

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
  api.getPublicKey({actor: null, publicKey}, (err, result) => {
    if(err) {
      return callback(err);
    }
    const {publicKey} = result;
    callback(null, publicKey);
  });
}
