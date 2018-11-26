#!/usr/bin/env python

# Copyright 2017 Google, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and

import argparse

from google.cloud import kms_v1
from google.cloud.kms_v1 import enums


# [START kms_create_keyring]
def create_key_ring(project_id, location_id, key_ring_id):
    """Creates a KeyRing in the given location (e.g. global)."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # The resource name of the location associated with the KeyRing.
    parent = client.location_path(project_id, location_id)

    # The keyring object template
    keyring = {'name': client.key_ring_path(project_id, location_id, key_ring_id)}

    # Create KeyRing
    response = client.create_key_ring(parent, key_ring_id, keyring)

    print('Created KeyRing {}.'.format(response.name))
# [END kms_create_keyring]


# [START kms_create_cryptokey]
def create_crypto_key(project_id, location_id, key_ring_id, crypto_key_id):
    """Creates a CryptoKey within a KeyRing in the given location."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # The resource name of the KeyRing associated with the CryptoKey.
    parent = client.key_ring_path(project_id, location_id, key_ring_id)

    # create the CryptoKey object template
    purpose = enums.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    crypto_key = {'purpose': purpose}

    # Create a CryptoKey for the given KeyRing.
    response = client.create_crypto_key(parent, crypto_key_id, crypto_key)

    print('Created CryptoKey {}.'.format(response.name))
# [END kms_create_cryptokey]


# [START kms_encrypt]
def encrypt_symmetric(project_id, location_id, key_ring_id, crypto_key_id,
                      plaintext):
    """Encrypts input plaintext data using the provided symmetric CryptoKey."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # The resource name of the CryptoKey.
    name = client.crypto_key_path_path(project_id, location_id, key_ring_id,
                                       crypto_key_id)

    # Use the KMS API to encrypt the data.
    response = client.encrypt(name, plaintext)
    return response.ciphertext
# [END kms_encrypt]


# [START kms_decrypt]
def decrypt_symmetric(project_id, location_id, key_ring_id, crypto_key_id,
                       ciphertext):
    """Decrypts input ciphertext using the provided symmetric CryptoKey."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # The resource name of the CryptoKey.
    name = client.crypto_key_path_path(project_id, location_id, key_ring_id,
                                       crypto_key_id)
    # Use the KMS API to decrypt the data.
    response = client.decrypt(name, ciphertext)
    return response.plaintext
# [END kms_decrypt]


# [START kms_disable_cryptokey_version]
def disable_crypto_key_version(project_id, location_id, key_ring_id,
                               crypto_key_id, version_id):
    """Disables a CryptoKeyVersion associated with a given CryptoKey and
    KeyRing."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # Construct the resource name of the CryptoKeyVersion.
    name = client.crypto_key_version_path(project_id, location_id, key_ring_id,
                                          crypto_key_id, version_id)

    # Use the KMS API to disable the CryptoKeyVersion.
    crypto_key_version = {'name': name, 'state': enums.CryptoKeyVersion.CryptoKeyVersionState.DISABLED}
    update_mask = {'paths': ["state"]}

    response = client.update_crypto_key_version(crypto_key_version, update_mask)
    print('CryptoKeyVersion {}\'s state has been set to {}.'.format(
        name, response.state))
# [END kms_disable_cryptokey_version]


# [START kms_enable_cryptokey_version]
def enable_crypto_key_version(project_id, location_id, key_ring_id,
                              crypto_key_id, version_id):
    """Enables a CryptoKeyVersion associated with a given CryptoKey and
    KeyRing."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # Construct the resource name of the CryptoKeyVersion.
    name = client.crypto_key_version_path(project_id, location_id, key_ring_id,
                                          crypto_key_id, version_id)

    # Use the KMS API to disable the CryptoKeyVersion.
    crypto_key_version = {'name': name, 'state': enums.CryptoKeyVersion.CryptoKeyVersionState.ENABLED}
    update_mask = {'paths': ["state"]}

    response = client.update_crypto_key_version(crypto_key_version, update_mask)
    print('CryptoKeyVersion {}\'s state has been set to {}.'.format(
        name, response.state))
# [END kms_enable_cryptokey_version]


# [START kms_destroy_cryptokey_version]
def destroy_crypto_key_version(
        project_id, location_id, key_ring_id, crypto_key_id, version_id):
    """Schedules a CryptoKeyVersion associated with a given CryptoKey and
    KeyRing for destruction 24 hours in the future."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # Construct the resource name of the CryptoKeyVersion.
    name = client.crypto_key_version_path(project_id, location_id, key_ring_id,
                                          crypto_key_id, version_id)

    # Use the KMS API to mark the CryptoKeyVersion for destruction.
    response = client.destroy_crypto_key_version(name)

    print('CryptoKeyVersion {}\'s state has been set to {}.'.format(
        name, response.state))
# [END kms_destroy_cryptokey_version]


# [START kms_restore_cryptokey_version]
def restore_crypto_key_version(
        project_id, location_id, key_ring_id, crypto_key_id, version_id):
    """Restores a CryptoKeyVersion that is scheduled for destruction."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # Construct the resource name of the CryptoKeyVersion.
    name = client.crypto_key_version_path(project_id, location_id, key_ring_id,
                                          crypto_key_id, version_id)

    # Use the KMS API to restore the CryptoKeyVersion.
    response = client.restore_crypto_key_version(name)

    print('CryptoKeyVersion {}\'s state has been set to {}.'.format(
        name, response.state))


# [END kms_restore_cryptokey_version]


# [START kms_add_member_to_cryptokey_policy]
def add_member_to_crypto_key_policy(
        project_id, location_id, key_ring_id, crypto_key_id, member, role):
    """Adds a member with a given role to the Identity and Access Management
    (IAM) policy for a given CryptoKey associated with a KeyRing."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # The resource name of the CryptoKey.
    resource = client.crypto_key_path_path(project_id, location_id, key_ring_id,
                                           crypto_key_id)
    # Get the current IAM policy and add the new member to it.
    policy = client.get_iam_policy(resource)

    # Add member
    old_bindings = list(policy.bindings)
    found = False
    for b in old_bindings:
        if b['role'] == role:
            found = True
            if member not in b['members']:
                b['members'].append(member)
    if not found:
        new_binding = {'role': role, 'members': [member]}
        old_bindings.append(new_binding)
    new_policy = {'version': policy.version,
                  'etag': policy.etag,
                  'bindings': old_bindings}

    # Set the new IAM Policy.
    client.set_iam_policy(resource, new_policy)
    print_msg = (
        'Member {} added with role {} to policy for CryptoKey {} in KeyRing {}'
        .format(member, role, crypto_key_id, key_ring_id))
    print(print_msg)
# [END kms_add_member_to_cryptokey_policy]


# [START kms_get_keyring_policy]
def get_key_ring_policy(project_id, location_id, key_ring_id):
    """Gets the Identity and Access Management (IAM) policy for a given KeyRing
    and prints out roles and the members assigned to those roles."""

    # Creates an API client for the KMS API.
    client = kms_v1.KeyManagementServiceClient()

    # The resource name of the CryptoKey.
    resource = client.key_ring_path(project_id, location_id, key_ring_id)

    # Get the current IAM policy and add the new member to it.
    policy = client.get_iam_policy(resource)

    print('Printing IAM policy for resource {}:'.format(resource))
    for b in policy.bindings:
        for m in b['members']:
            print('Role: {} Member: {}'.format(b['role'], m))
    return policy

# [END kms_get_keyring_policy]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest='command')

    create_key_ring_parser = subparsers.add_parser('create_key_ring')
    create_key_ring_parser.add_argument('project')
    create_key_ring_parser.add_argument('location')
    create_key_ring_parser.add_argument('key_ring')

    create_crypto_key_parser = subparsers.add_parser('create_crypto_key')
    create_crypto_key_parser.add_argument('project')
    create_crypto_key_parser.add_argument('location')
    create_crypto_key_parser.add_argument('key_ring')
    create_crypto_key_parser.add_argument('crypto_key')

    encrypt_parser = subparsers.add_parser('encrypt')
    encrypt_parser.add_argument('project')
    encrypt_parser.add_argument('location')
    encrypt_parser.add_argument('key_ring')
    encrypt_parser.add_argument('crypto_key')
    encrypt_parser.add_argument('infile')
    encrypt_parser.add_argument('outfile')

    decrypt_parser = subparsers.add_parser('decrypt')
    decrypt_parser.add_argument('project')
    decrypt_parser.add_argument('location')
    decrypt_parser.add_argument('key_ring')
    decrypt_parser.add_argument('crypto_key')
    decrypt_parser.add_argument('infile')
    decrypt_parser.add_argument('outfile')

    disable_crypto_key_version_parser = subparsers.add_parser(
        'disable_crypto_key_version')
    disable_crypto_key_version_parser.add_argument('project')
    disable_crypto_key_version_parser.add_argument('location')
    disable_crypto_key_version_parser.add_argument('key_ring')
    disable_crypto_key_version_parser.add_argument('crypto_key')
    disable_crypto_key_version_parser.add_argument('version')

    enable_crypto_key_version_parser = subparsers.add_parser(
        'enable_crypto_key_version')
    enable_crypto_key_version_parser.add_argument('project')
    enable_crypto_key_version_parser.add_argument('location')
    enable_crypto_key_version_parser.add_argument('key_ring')
    enable_crypto_key_version_parser.add_argument('crypto_key')
    enable_crypto_key_version_parser.add_argument('version')

    destroy_crypto_key_version_parser = subparsers.add_parser(
        'destroy_crypto_key_version')
    destroy_crypto_key_version_parser.add_argument('project')
    destroy_crypto_key_version_parser.add_argument('location')
    destroy_crypto_key_version_parser.add_argument('key_ring')
    destroy_crypto_key_version_parser.add_argument('crypto_key')
    destroy_crypto_key_version_parser.add_argument('version')

    restore_crypto_key_version_parser = subparsers.add_parser(
        'restore_crypto_key_version')
    restore_crypto_key_version_parser.add_argument('project')
    restore_crypto_key_version_parser.add_argument('location')
    restore_crypto_key_version_parser.add_argument('key_ring')
    restore_crypto_key_version_parser.add_argument('crypto_key')
    restore_crypto_key_version_parser.add_argument('version')

    add_member_to_crypto_key_policy_parser = subparsers.add_parser(
        'add_member_to_crypto_key_policy')
    add_member_to_crypto_key_policy_parser.add_argument('project')
    add_member_to_crypto_key_policy_parser.add_argument('location')
    add_member_to_crypto_key_policy_parser.add_argument('key_ring')
    add_member_to_crypto_key_policy_parser.add_argument('crypto_key')
    add_member_to_crypto_key_policy_parser.add_argument('member')
    add_member_to_crypto_key_policy_parser.add_argument('role')

    get_key_ring_policy_parser = subparsers.add_parser('get_key_ring_policy')
    get_key_ring_policy_parser.add_argument('project')
    get_key_ring_policy_parser.add_argument('location')
    get_key_ring_policy_parser.add_argument('key_ring')

    args = parser.parse_args()

    if args.command == 'create_key_ring':
        create_key_ring(
            args.project,
            args.location,
            args.key_ring)
    elif args.command == 'create_crypto_key':
        create_crypto_key(
            args.project,
            args.location,
            args.key_ring,
            args.crypto_key)
    elif args.command == 'encrypt':
        encrypt_symmetric(
            args.project,
            args.location,
            args.key_ring,
            args.crypto_key,
            args.infile,
            args.outfile)
    elif args.command == 'decrypt':
        decrypt_symmetric(
            args.project,
            args.location,
            args.key_ring,
            args.crypto_key,
            args.infile,
            args.outfile)
    elif args.command == 'disable_crypto_key_version':
        disable_crypto_key_version(
            args.project,
            args.location,
            args.key_ring,
            args.crypto_key,
            args.version)
    elif args.command == 'enable_crypto_key_version':
        enable_crypto_key_version(
            args.project,
            args.location,
            args.key_ring,
            args.crypto_key,
            args.version)
    elif args.command == 'destroy_crypto_key_version':
        destroy_crypto_key_version(
            args.project,
            args.location,
            args.key_ring,
            args.crypto_key,
            args.version)
    elif args.command == 'restore_crypto_key_version':
        restore_crypto_key_version(
            args.project,
            args.location,
            args.key_ring,
            args.crypto_key,
            args.version)
    elif args.command == 'add_member_to_crypto_key_policy':
        add_member_to_crypto_key_policy(
            args.project,
            args.location,
            args.key_ring,
            args.crypto_key,
            args.member,
            args.role)
    elif args.command == 'get_key_ring_policy':
        get_key_ring_policy(
            args.project,
            args.location,
            args.key_ring)
