/*
 * Copyright (c) 2015-2017 Digital Bazaar, Inc. All rights reserved.
 */

'use strict';

var helpers = require('./helpers');

var mock = {};
module.exports = mock;

var identities = mock.identities = {};
var userName;

// identity with permission to add public keys
userName = 'regularUser';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].identity.sysResourceRole.push({
  sysRole: 'bedrock-key.test',
  generateResource: 'id'
});

// identity with permission to add public keys
userName = 'regularUser2';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].identity.sysResourceRole.push({
  sysRole: 'bedrock-key.test',
  generateResource: 'id'
});

// identity with permission to access all public keys (Admin)
userName = 'adminUser';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);
identities[userName].identity.sysResourceRole.push({
  sysRole: 'bedrock-key.test'
});

// identity with no permissions
userName = 'noPermissionUser';
identities[userName] = {};
identities[userName].identity = helpers.createIdentity(userName);

mock.goodKeyPair = {
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArpPmWDG3MCn3simEGNIe\n' +
    'seNe3epn81gLnWXjup458yXgjUYFqKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQ\n' +
    'mmQjh28BhMXHq94HgQ90nKQ3KTpAMOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o\n' +
    '9OhzpqJwFzQj7Nxx2dg/3LnkcsP1/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3Wrnmn\n' +
    'LxNEwvWKj3iDp4JyLeV3WxWIf3ExgdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J\n' +
    '8xqsqrvR3ICdYIevjFknMHX1LZB5R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYy\n' +
    'jwIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpQIBAAKCAQEArpPmWDG3MCn3simEGNIeseNe3epn81gLnWXjup458yXgjUYF\n' +
    'qKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQmmQjh28BhMXHq94HgQ90nKQ3KTpA\n' +
    'MOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o9OhzpqJwFzQj7Nxx2dg/3LnkcsP1\n' +
    '/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3WrnmnLxNEwvWKj3iDp4JyLeV3WxWIf3Ex\n' +
    'gdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J8xqsqrvR3ICdYIevjFknMHX1LZB5\n' +
    'R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYyjwIDAQABAoIBAQCJZBpfBFlQDWdD\n' +
    'jorIYe0IQJGzgjvm9j7F058iik2+/us3I4lmjnPGkYlEs4uAn7df087pVOhEDatp\n' +
    'D0r2bTZ92xtfBcyjKmgW6XjsaDZ05IQI7TABi4lnXAD9wWWU5hXqfpLT6UPvQArx\n' +
    'xBWclR8mRx5lYOdoS3+OdHshX5/63ACCYlYonTov2TkIjvozQY4H5F0M0aaF3naM\n' +
    'GFRus8qmJTrfBmQPBBwRJnPJLQk03hAHXRyUHGHAo5QVZlEdvf5LeOTIfsw2X9ro\n' +
    'xGFBIruS2JfrWHbApTOIYlzCQBpBBM28l4/rvkfEDmugYaZE9LdpQfddQJOrnqXF\n' +
    'xHARbO0JAoGBANjqe0YKPsW/i6MEN0kOhcpYm19GYceXTSgErDsTDeEcvv6o9Chi\n' +
    'baRyNK1tZ+Kff4rMw74Vw+uIfpq5ROiTJ67p094jVmZhgmKsXAqIbapcR+R+bygO\n' +
    'Q3UioXCTCYvPKWL8n8FdgFsBohK4+y5NCgNZ8tIxqvB1fLQDs9AdhOxjAoGBAM4I\n' +
    'g/fUY5oBFS4KrMCQbz+DPzDTgMGrX0ZC7BD6S9jX/AI4Wwm11t/WWGuijUiQaFFd\n' +
    'YUHXVoe6qRuYemND2zUvbpBK84SVVxF3a6lncmpnxiLe2lHbj5/Dh+y/C7HKGiTC\n' +
    'jTfvfe8YAeTpC1djIH0sWPC6n91ulyA23Nz4h6rlAoGBAJVUT0s3cGF4bSvrkhfU\n' +
    'TJyxhT0A2f2qlm5PUTZV9r8bqAzuyS8oG60TBlrCL7te7FHkh3jLyRXT4LypgNvP\n' +
    'uoj65mVN1IQk6rr9R1vk8gJPBxsxQ1rC/wObtKIoR3EdS7OekGhw8xUzuZzEBf+o\n' +
    '/5SxDq5PjQt/BjtzNQ231LNbAoGAGDab+8Y0Jmc2LAEJKGBREq/D/2L74MbZHZLD\n' +
    '14Ly4vsPHNuup0d9hzTTk2K5I+wEtns48Nnzy2O+eAXFbGEPJAL9BWwpjk1WvDDC\n' +
    'sFf99E9Z08NI+RHKoUYDdWlGYJCV3fgXTJmSvUSfBF32/UAjE1Lg6PmlzAoxLJIG\n' +
    'BtoWZ5kCgYEAnvcfRx56ZvUkWJiSI0me+M20A74IGwxDPF87XuGPSEqcoLSc1qJM\n' +
    '6LtOFUE7nFVEqFMN2IhW59qb2eCg7XpeEQic4aqNkc8WtuMEavHRTucsEWk+ypZv\n' +
    'JCxLDG7o3iSqT+DNbYnDI7aUCuM6Guji98q3IvBnW5hj+jbmo4sfRDQ=\n' +
    '-----END RSA PRIVATE KEY-----\n'
};

mock.goodKeyPair2 = {
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8uiQkqJ/rbKE/W3ofA4\n' +
    'U/QbQ5TSHq8tkCNTfoJX7vpJRS3aVw7Etz3BNVfOPAPkqf2pxdTxdsdHO6K0PWkz\n' +
    'JTk3gRTvtUpFa2tavMDjm2WwYKM1uXTJwj968r2n5yzf7zZ1PeXU3Vy0JGOriDnM\n' +
    'Xg+FrywLYYwEtewPkK3DcpmQOh0ZhLr7PEGrLU3NxiT0yYkcflNEojfx7ONko0jS\n' +
    'zbfHM0Erf7dcbNSAG6HwvtfaW6LKOOzgkZ2jcVOoR5iOMkRLFzOnfist11tMPpL3\n' +
    'cVlCyJS41LagsJZsjjskmh4eWs28v84j4syk/f8ru/AkTmNp3LvPAEFI8z+kdmYx\n' +
    '0QIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEAy8uiQkqJ/rbKE/W3ofA4U/QbQ5TSHq8tkCNTfoJX7vpJRS3a\n' +
    'Vw7Etz3BNVfOPAPkqf2pxdTxdsdHO6K0PWkzJTk3gRTvtUpFa2tavMDjm2WwYKM1\n' +
    'uXTJwj968r2n5yzf7zZ1PeXU3Vy0JGOriDnMXg+FrywLYYwEtewPkK3DcpmQOh0Z\n' +
    'hLr7PEGrLU3NxiT0yYkcflNEojfx7ONko0jSzbfHM0Erf7dcbNSAG6HwvtfaW6LK\n' +
    'OOzgkZ2jcVOoR5iOMkRLFzOnfist11tMPpL3cVlCyJS41LagsJZsjjskmh4eWs28\n' +
    'v84j4syk/f8ru/AkTmNp3LvPAEFI8z+kdmYx0QIDAQABAoIBAGxHvOWl/x4D9uiW\n' +
    'BMSZAwSwTZAh0WaWQwozithL3vbNqwKDs1/QK/sEZ9S025INq4AalArV8pneld18\n' +
    'vHFopNEhTnlaK2bSmIHTn3lsr0JQzF78OL5Z7B02Z1f0JvLwZ+cMs0x5Ahm/eMNg\n' +
    '5bHSq+BKNQh2yXFB2Prj+v0vJgqL06RP9AkmidjI1p/fFJN3K3cf5FYZ7LAlF2Kz\n' +
    'gw5TeH2BePDw6njjBUGJ9AjGqnvivJh+0i00/doX/dGg7hvVFxQLWjj9SwUBl/3f\n' +
    'mfnG+jUH9PLO+KBVwlBOt2wwVpmp+PPfvqPCRJnelYSiphoKl1jioFVJ+f6aJrbk\n' +
    'um0DDzECgYEA9pCmwr5IOdO2j3XVsYS8mu4Jqc9b2cFCt1DbQ2HusGkvF0Nyhgpo\n' +
    'v8dzvaIXiMyo4Rql15GaK3b8Pd4IroPELXaWULe2KhmthF/BYslXu2i2M4N6VMBC\n' +
    'sJaExd4wMaQrqEOB4rV04V8X8A/YRNBG4SIMjZtgEjjIdz00BgPxXV0CgYEA05gD\n' +
    'CWr6rz1PLDWG2t8E6tHZe66l/zW6DpwoUXha4rX6eBa6qS4DIQjelx9oow0W+xy3\n' +
    '2ZN8iClMckZdVdHVXvt9pQ8o4l5VNF7KphFZWRLY9r0I9Nf3UZR6RTtVVkUdiA2D\n' +
    'Xo/SpOdb/RwGyJinPsBPlnboPpv2YTRzUJ836wUCgYEApGjICcs/9e9KKFb2ayyL\n' +
    'ZvOa1fRC1uybRAlSa5f9xPwePnDnCKIgPuEMOELBVqLBaXiPZTLdjmYExGwtddC/\n' +
    'G2Gb0a7udRwyK7Z+CRUgvwKPm8Hr7F9XGNEFL7t8f11tDwIUtcsxaKY0HAs0to36\n' +
    '9Vvy6unUIdJjOb9B1VEDvLECgYBtGfR25rJbqUEpim/+awAeFBYPr/3nmcxVvC8N\n' +
    '0wEJ5MtBIHcexJrYbbpYMdnCOP2gfS5PAb00eBby1VVK6ucaEpK2iRqLnhhQ6I+V\n' +
    'EV0AkLdOgiocFT9w0R46lF1sHjcb79vM5lu2q5TC7bCRviR+NqrS6nzVy5U+iczr\n' +
    'xS0QAQKBgBuNF/C9lctENVsP5sm/Uxlx0pmkSIArxWQEUQZ/4pznalS3pRiDkFgF\n' +
    '9JsHo8vewA6WCZ/UBQC3T2HH0NUEezvdwehHT3mbtElfXvvt6sUjCFN2v/cDRPBp\n' +
    'wHgbbc5edS/Y+RKEVgylsnXYN+jKf08y4lx2quyypONMeqyGr4Gn\n' +
    '-----END RSA PRIVATE KEY-----\n'
};

// the public and private keys are valid, but do not match
mock.badKeyPair = {
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwWDnqsCB2eYSGicntVHU\n' +
    '1nqzBdlInoLkNzrjp5nd7b57kZQwJteYtlnjVa4WD39iNnJbsLlpFsUJSL7TvgzC\n' +
    'JNuey9/6QvYpZNuXz2a8EdOA0tPu6GmVdV5ZW7eJRWUZXhE01nrHbfGVWqU5xVy6\n' +
    'mcI9JB+vc151sleyrdVZkt+MvZy9D1gMre/bb8AM6YxkMoW/kwhkDpu6LcX8xhws\n' +
    'MmX0+W+i2BKauSDNrooRpFJhPBsvAJc2a8QN8Qa2QOrDEANR/h+hS66/A/TGNNcl\n' +
    'eItkVXFDeLhta724RXHwhY4mJN9xU9/B6TPtz4v0NCpB6t8UyDw6lxRJM5ws3wM1\n' +
    'lQIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpQIBAAKCAQEArpPmWDG3MCn3simEGNIeseNe3epn81gLnWXjup458yXgjUYF\n' +
    'qKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQmmQjh28BhMXHq94HgQ90nKQ3KTpA\n' +
    'MOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o9OhzpqJwFzQj7Nxx2dg/3LnkcsP1\n' +
    '/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3WrnmnLxNEwvWKj3iDp4JyLeV3WxWIf3Ex\n' +
    'gdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J8xqsqrvR3ICdYIevjFknMHX1LZB5\n' +
    'R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYyjwIDAQABAoIBAQCJZBpfBFlQDWdD\n' +
    'jorIYe0IQJGzgjvm9j7F058iik2+/us3I4lmjnPGkYlEs4uAn7df087pVOhEDatp\n' +
    'D0r2bTZ92xtfBcyjKmgW6XjsaDZ05IQI7TABi4lnXAD9wWWU5hXqfpLT6UPvQArx\n' +
    'xBWclR8mRx5lYOdoS3+OdHshX5/63ACCYlYonTov2TkIjvozQY4H5F0M0aaF3naM\n' +
    'GFRus8qmJTrfBmQPBBwRJnPJLQk03hAHXRyUHGHAo5QVZlEdvf5LeOTIfsw2X9ro\n' +
    'xGFBIruS2JfrWHbApTOIYlzCQBpBBM28l4/rvkfEDmugYaZE9LdpQfddQJOrnqXF\n' +
    'xHARbO0JAoGBANjqe0YKPsW/i6MEN0kOhcpYm19GYceXTSgErDsTDeEcvv6o9Chi\n' +
    'baRyNK1tZ+Kff4rMw74Vw+uIfpq5ROiTJ67p094jVmZhgmKsXAqIbapcR+R+bygO\n' +
    'Q3UioXCTCYvPKWL8n8FdgFsBohK4+y5NCgNZ8tIxqvB1fLQDs9AdhOxjAoGBAM4I\n' +
    'g/fUY5oBFS4KrMCQbz+DPzDTgMGrX0ZC7BD6S9jX/AI4Wwm11t/WWGuijUiQaFFd\n' +
    'YUHXVoe6qRuYemND2zUvbpBK84SVVxF3a6lncmpnxiLe2lHbj5/Dh+y/C7HKGiTC\n' +
    'jTfvfe8YAeTpC1djIH0sWPC6n91ulyA23Nz4h6rlAoGBAJVUT0s3cGF4bSvrkhfU\n' +
    'TJyxhT0A2f2qlm5PUTZV9r8bqAzuyS8oG60TBlrCL7te7FHkh3jLyRXT4LypgNvP\n' +
    'uoj65mVN1IQk6rr9R1vk8gJPBxsxQ1rC/wObtKIoR3EdS7OekGhw8xUzuZzEBf+o\n' +
    '/5SxDq5PjQt/BjtzNQ231LNbAoGAGDab+8Y0Jmc2LAEJKGBREq/D/2L74MbZHZLD\n' +
    '14Ly4vsPHNuup0d9hzTTk2K5I+wEtns48Nnzy2O+eAXFbGEPJAL9BWwpjk1WvDDC\n' +
    'sFf99E9Z08NI+RHKoUYDdWlGYJCV3fgXTJmSvUSfBF32/UAjE1Lg6PmlzAoxLJIG\n' +
    'BtoWZ5kCgYEAnvcfRx56ZvUkWJiSI0me+M20A74IGwxDPF87XuGPSEqcoLSc1qJM\n' +
    '6LtOFUE7nFVEqFMN2IhW59qb2eCg7XpeEQic4aqNkc8WtuMEavHRTucsEWk+ypZv\n' +
    'JCxLDG7o3iSqT+DNbYnDI7aUCuM6Guji98q3IvBnW5hj+jbmo4sfRDQ=\n' +
    '-----END RSA PRIVATE KEY-----\n'
};

// the public key is invalid, the private key is valid
mock.badPublicKey = {
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
    'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' +
    '-----END PUBLIC KEY-----\n',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpQIBAAKCAQEArpPmWDG3MCn3simEGNIeseNe3epn81gLnWXjup458yXgjUYF\n' +
    'qKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQmmQjh28BhMXHq94HgQ90nKQ3KTpA\n' +
    'MOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o9OhzpqJwFzQj7Nxx2dg/3LnkcsP1\n' +
    '/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3WrnmnLxNEwvWKj3iDp4JyLeV3WxWIf3Ex\n' +
    'gdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J8xqsqrvR3ICdYIevjFknMHX1LZB5\n' +
    'R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYyjwIDAQABAoIBAQCJZBpfBFlQDWdD\n' +
    'jorIYe0IQJGzgjvm9j7F058iik2+/us3I4lmjnPGkYlEs4uAn7df087pVOhEDatp\n' +
    'D0r2bTZ92xtfBcyjKmgW6XjsaDZ05IQI7TABi4lnXAD9wWWU5hXqfpLT6UPvQArx\n' +
    'xBWclR8mRx5lYOdoS3+OdHshX5/63ACCYlYonTov2TkIjvozQY4H5F0M0aaF3naM\n' +
    'GFRus8qmJTrfBmQPBBwRJnPJLQk03hAHXRyUHGHAo5QVZlEdvf5LeOTIfsw2X9ro\n' +
    'xGFBIruS2JfrWHbApTOIYlzCQBpBBM28l4/rvkfEDmugYaZE9LdpQfddQJOrnqXF\n' +
    'xHARbO0JAoGBANjqe0YKPsW/i6MEN0kOhcpYm19GYceXTSgErDsTDeEcvv6o9Chi\n' +
    'baRyNK1tZ+Kff4rMw74Vw+uIfpq5ROiTJ67p094jVmZhgmKsXAqIbapcR+R+bygO\n' +
    'Q3UioXCTCYvPKWL8n8FdgFsBohK4+y5NCgNZ8tIxqvB1fLQDs9AdhOxjAoGBAM4I\n' +
    'g/fUY5oBFS4KrMCQbz+DPzDTgMGrX0ZC7BD6S9jX/AI4Wwm11t/WWGuijUiQaFFd\n' +
    'YUHXVoe6qRuYemND2zUvbpBK84SVVxF3a6lncmpnxiLe2lHbj5/Dh+y/C7HKGiTC\n' +
    'jTfvfe8YAeTpC1djIH0sWPC6n91ulyA23Nz4h6rlAoGBAJVUT0s3cGF4bSvrkhfU\n' +
    'TJyxhT0A2f2qlm5PUTZV9r8bqAzuyS8oG60TBlrCL7te7FHkh3jLyRXT4LypgNvP\n' +
    'uoj65mVN1IQk6rr9R1vk8gJPBxsxQ1rC/wObtKIoR3EdS7OekGhw8xUzuZzEBf+o\n' +
    '/5SxDq5PjQt/BjtzNQ231LNbAoGAGDab+8Y0Jmc2LAEJKGBREq/D/2L74MbZHZLD\n' +
    '14Ly4vsPHNuup0d9hzTTk2K5I+wEtns48Nnzy2O+eAXFbGEPJAL9BWwpjk1WvDDC\n' +
    'sFf99E9Z08NI+RHKoUYDdWlGYJCV3fgXTJmSvUSfBF32/UAjE1Lg6PmlzAoxLJIG\n' +
    'BtoWZ5kCgYEAnvcfRx56ZvUkWJiSI0me+M20A74IGwxDPF87XuGPSEqcoLSc1qJM\n' +
    '6LtOFUE7nFVEqFMN2IhW59qb2eCg7XpeEQic4aqNkc8WtuMEavHRTucsEWk+ypZv\n' +
    'JCxLDG7o3iSqT+DNbYnDI7aUCuM6Guji98q3IvBnW5hj+jbmo4sfRDQ=\n' +
    '-----END RSA PRIVATE KEY-----\n'
};

// the public key is valid, the private key is invalid
mock.badPrivateKey = {
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\n' +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArpPmWDG3MCn3simEGNIe\n' +
    'seNe3epn81gLnWXjup458yXgjUYFqKcFlsV5oW4vSF5EEQfPqWB+E5NWYfE9IioQ\n' +
    'mmQjh28BhMXHq94HgQ90nKQ3KTpAMOXNefvcun+qqOyr4Jf8y8esiYHjuitZA03o\n' +
    '9OhzpqJwFzQj7Nxx2dg/3LnkcsP1/RtY5zxnyEGEnxR+Sy+bPXEMbBk0+C3Wrnmn\n' +
    'LxNEwvWKj3iDp4JyLeV3WxWIf3ExgdkOWv3DwVo7pPmrSg+kQaU20QxQycY2xW7J\n' +
    '8xqsqrvR3ICdYIevjFknMHX1LZB5R6nfosG90pWVA2m5LqnAoEMBnG/CUpvxPRYy\n' +
    'jwIDAQAB\n' +
    '-----END PUBLIC KEY-----\n',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n' +
    'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' +
    '-----END RSA PRIVATE KEY-----\n'
};
