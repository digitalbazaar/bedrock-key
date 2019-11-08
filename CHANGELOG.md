# bedrock-key ChangeLog

### Changed
- Update max bedrock dependency.

# 5.1.3 - 2019-11-07

### Changed
- Update to latest bedrock events API.

# 5.1.2 - 2018-08-02

### Fixed
- Decode base58 before checking key length.

# 5.1.1 - 2018-06-25

### Fixed
- Fix internal `addPublicKey` call.

# 5.1.0 - 2018-06-15

### Added
- Add promise-based API.

# 5.0.0 - 2018-06-14

### Added
- Support Ed25519 keys.

### Changed
- **Breaking** Change the compound index on `owner` and `pem` to a partial
  non-unique index. This is in support of storing keys that are not in PEM
  format.
- **Breaking** Return `DuplicateError` on an attempt to add key with duplicate
  `id` instead of a `MongoError`.
- **Breaking** The `getPublicKey` API now returns an object as its second
  argument. This is in support of implementing a Promise API in the future.
- **Breaking** Update all APIs to use named parameters.  

# 4.1.0 - 2018-02-24

### Changed
- Use ES6 Syntax.
- Update bedrock-mongodb dependency.
- Upgrade to Async@2.

### Added
- Optional caching of public keys. The current caching implementation is
  aimed at accelerating http-signature authentication `bedrock-passport`.

## 4.0.0 - 2017-06-20

### Changed
- **Breaking** Remove `generatePublicKeyId` API.
- Update `bedrock` dependency to v1.4.x.
- Remove `bedrock-server` dependency.
- Remove `ursa` dependency.

### Fixed
- Fix permissions issues in `getPublicKey` and `revokePublicKey` APIs.

### Added
- Add 46 additional tests.

## 3.1.4 - 2016-09-22

### Changed
- Restructure test framework for CI.

## 3.1.3 - 2016-08-03

### Fixed
- Check proper resource in permission check.

## 3.1.2 - 2016-06-09

### Fixed
- Allow authenticated users to view public key data.

## 3.1.1 - 2016-06-07

### Changed
- Update dependencies.

## 3.1.0 - 2016-05-27

### Added
- Option to filter by a `capability` parameter in getPublicKeys.

## 3.0.0 - 2016-04-28

### Added
- Add additional PUBLIC_KEY permissions.

### Changed
- Replaced IDENTITY permissions with PUBLIC_KEY permissions.

## 2.0.2 - 2016-04-26

## 2.0.1 - 2016-04-15

### Changed
- Update bedrock dependencies.

## 2.0.0 - 2016-03-02

### Changed
- Update package dependencies for npm v3 compatibility.

## 1.0.0 - 2016-01-31

- See git history for changes.
