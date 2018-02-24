# bedrock-key ChangeLog

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
- **Breaking** Removed `generatePublicKeyId` API.
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
