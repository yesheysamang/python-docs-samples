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

import time
from os import environ

from google.cloud import kms_v1
from google.cloud.kms_v1 import enums
from google.iam.v1.policy_pb2 import Policy

import pytest

import snippets


class TestKMSSnippets:

    project_id = environ['GCLOUD_PROJECT']
    keyring_id = 'kms-samples'
    location = 'global'
    parent = 'projects/{}/locations/{}'.format(project_id, location)
    keyring_path = '{}/keyRings/{}'.format(parent, keyring_id)
    version = '1'

    symId = 'symmetric'

    sym = '{}/cryptoKeys/{}'.format(keyring_path, symId)
    sym_version = '{}/cryptoKeyVersions/{}'.format(sym, version)

    message = 'test message 123'
    message_bytes = message.encode('utf-8')

    member = 'group:test@google.com'
    role = 'roles/viewer'

    @pytest.mark.skip(reason="There's currently no method to delete keyrings, \
                              so we should avoid creating resources")
    def test_create_key_ring(self):
        ring_id = self.keyring_id + '-testcreate' + str(int(time.time()))
        snippets.create_key_ring(self.project_id, self.location, ring_id)
        client = kms_v1.KeyManagementServiceClient()
        result = client.get_key_ring(client.key_ring_path(self.project_id,
                                                          self.location,
                                                          ring_id))
        assert ring_id in result.name

    @pytest.mark.skip(reason="Deleting keys isn't instant, so we should avoid \
                              creating a large number of them in our tests")
    def test_create_crypto_key(self):
        key_id = self.symId + '-test' + str(int(time.time()))
        snippets.create_crypto_key(self.project_id, self.location,
                                   self.keyring_id, key_id)
        c = kms_v1.KeyManagementServiceClient()
        result = c.get_crypto_key(c.crypto_key_path(self.project_id,
                                                    self.location,
                                                    self.keyring_id,
                                                    key_id))
        assert key_id in result.name

    # tests disable/enable/destroy/restore
    def test_key_change_version_state(self):
        client = kms_v1.KeyManagementServiceClient()
        name = client.crypto_key_version_path(self.project_id, self.location,
                                              self.keyring_id, self.symId,
                                              self.version)
        state_enum = enums.CryptoKeyVersion.CryptoKeyVersionState
        # test disable
        snippets.disable_crypto_key_version(self.project_id, self.location,
                                            self.keyring_id, self.symId,
                                            self.version)
        response = client.get_crypto_key_version(name)
        assert response.state == state_enum.DISABLED
        # test destroy
        snippets.destroy_crypto_key_version(self.project_id, self.location,
                                            self.keyring_id, self.symId,
                                            self.version)
        response = client.get_crypto_key_version(name)
        assert response.state == state_enum.DESTROY_SCHEDULED
        # test restore
        snippets.restore_crypto_key_version(self.project_id, self.location,
                                            self.keyring_id, self.symId,
                                            self.version)
        response = client.get_crypto_key_version(name)
        assert response.state == state_enum.DISABLED
        # test re-enable
        snippets.enable_crypto_key_version(self.project_id, self.location,
                                           self.keyring_id, self.symId,
                                           self.version)
        response = client.get_crypto_key_version(name)
        assert response.state == state_enum.ENABLED

    def test_get_ring_policy(self):
        policy = snippets.get_key_ring_policy(self.project_id,
                                              self.location, self.keyring_id)
        assert type(policy) is Policy

    def test_add_remove_member_ring(self):
        # add member
        snippets.add_member_to_key_ring_policy(self.project_id, self.location,
                                               self.keyring_id, self.member,
                                               self.role)
        policy = snippets.get_key_ring_policy(self.project_id,
                                              self.location, self.keyring_id)
        found = False
        for b in list(policy.bindings):
            if b.role == self.role and self.member in b.members:
                found = True
        assert found
        # remove member
        snippets.remove_member_from_key_ring_policy(self.project_id,
                                                    self.location,
                                                    self.keyring_id,
                                                    self.member,
                                                    self.role)
        policy = snippets.get_key_ring_policy(self.project_id,
                                              self.location, self.keyring_id)
        found = False
        for b in list(policy.bindings):
            if b.role == self.role and self.member in b.members:
                found = True
        assert not found

    def test_add_remove_member_key(self):
        assert False

    def test_symmetric_encrypt_decrypt(self):
        assert False
