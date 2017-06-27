# Copyright (c) 2017 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import json
import uuid
import logging

from rotating_keymaster_keywrap import KeyWrap
from swift.common.utils import get_logger
from swift.common.middleware.crypto.crypto_utils import Crypto

SYSMETA_X = 'X'
SYSMETA_ACCOUNT = 'Account'
SYSMETA_CONTAINER = 'Container'
SYSMETA_OBJECT = 'Object'
SYSMETA_SYSMETA = 'Sysmeta'
SYSMETA_ENC_PREFIX = 'Enc'
SYSMETA_TRANSIENT = 'Transient'

KEY_ID = 'key_id'
PARENT_ID = 'parent_id'
WRAPPED_KEK = 'wrapped_kek'
WRAPPED_DEK = 'wrapped_dek'
IV = 'iv'
REWRAP_POST_HEADER = 'Rewrap'
REKEY_POST_HEADER = 'Rekey'
PURGE_POST_HEADER = 'Purge'

# logging.ERROR goes into proxy-server.error
# logging.INFO goes into proxy-server.log
SECDEL_LOG_LEVEL_INFO = logging.ERROR
SECDEL_LOG_LEVEL_DEBUG = logging.ERROR
SECDEL_LOG_LEVEL_ERROR = logging.ERROR


def _header_to_env_var(key):
    """Convert header to wsgi env variable.
    :param key: http header name (ex. 'X-Auth-Token')
    :return wsgi env variable name (ex. 'HTTP_X_AUTH_TOKEN')
    """

    return 'HTTP_%s' % key.replace('-', '_').upper()


def get_header(env, key, default=None):
    """Get http header from environment."""

    env_key = _header_to_env_var(key)
    return env.get(env_key, default)


class KeyMaterial(object):
    """
    KeyMaterial class to hold the key material of a key encryption key in
    multiple different formats:
     - Wrapped, base64 format required for storing in Swift metadata
     - Unwrapped, binary format required for cryptographic operations
     - Other formats (temporarily) stored for testing and debugging, to be
       removed if/when deemed unnecessary FIXME
    """
    def __init__(self):
        self.wrapped_bytes = None
        self.unwrapped_bytes = None
        self.b64_encoded_wrapped_bytes = None
        self.b64_encoded_unwrapped_bytes = None
        self.logger = get_logger(conf=None,
                                 log_route="rotating_keymaster_helpers")

    def wrap(self, wrapping_key_material_bytes):
        """
        Wrap the key material with the KEK of the wrapping key. Requires that
        self.unwrapped_bytes is set. After the wrapping, all fields the
        KeyMaterial class are set (wrapped and unwrapped, Base64 encoded and
        unencoded).

        :param wrapping_key_material_bytes: the wrapping key that wraps/
                                            unwraps this KEK
        :type wrapping_key_material_bytes:  byte array
        """

        if self.unwrapped_bytes is None:
            if self.b64_encoded_unwrapped_bytes is None:
                raise ValueError(
                    "Neither unwrapped_bytes nor b64_encoded_unwrapped_bytes "
                    "set for key")
            self.unwrapped_bytes = base64.b64decode(
                self.b64_encoded_unwrapped_bytes)

        if self.wrapped_bytes is not None:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "Key already wrapped")
            return

        keywrap = KeyWrap
        self.wrapped_bytes = keywrap.wrap(wrapping_key_material_bytes,
                                          self.unwrapped_bytes)
        self.b64_encoded_wrapped_bytes = base64.b64encode(self.wrapped_bytes)
        self.b64_encoded_unwrapped_bytes = base64.b64encode(
            self.unwrapped_bytes)

    def unwrap(self, wrapping_key_material_bytes):
        """
        The wrapping_key can still be of type EntityKey, since we will always
        use the wrapping_key.kek_material to wrap/unwrap (never
        wrapping_key.dek_material).
        Unwrap the key material of this key using the wrapping key.

        :param wrapping_key_material_bytes: the wrapping key that wraps/
                                            unwraps this KEK
        :type wrapping_key_material_bytes:  byte array
        """

        if self.wrapped_bytes is None:
            if self.b64_encoded_wrapped_bytes is None:
                raise ValueError(
                    "Neither wrapped_bytes nor b64_encoded_wrapped_bytes "
                    "set for key")
            self.wrapped_bytes = base64.b64decode(
                self.b64_encoded_wrapped_bytes)

        if self.unwrapped_bytes is not None:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "Key already unwrapped")
            return

        keywrap = KeyWrap
        self.unwrapped_bytes = keywrap.unwrap(wrapping_key_material_bytes,
                                              self.wrapped_bytes)
        self.b64_encoded_unwrapped_bytes = base64.b64encode(
            self.unwrapped_bytes)


class EntityKey(object):
    """
    Create a new EntityKey. If no entity_key_id is specified, a new one is
    generated. This corresponds to the case where a key does not exist (e.g.,
    when uploading a new object). A case where a entity_key_id is specified is
    e.g., when reading an object and creating a KEK for the container key, in
    which case the container KEK id is read from the object KEK.

    :param entity_type: the type of EntityKey, e.g., 'Container' or 'Object'
    :type entity_type: string

    :param entity_key_id: the EntityKey ID, a Type 1 UUID as a string, from
        which a timestamp can be extracted and used to determine the version.
    :type entity_key_id: string

    :param value_dict: The EntityKey dict with values parsed from metadata
    :type value_dict: dict

    :param parent_kek_material: The wrapping key material of the parent key
                                when generating a new key
    :type parent_kek_material:  byte array

    :param parent_id: The ID of the parent key when generating a new key
    :type parent_id:  string

    :param unwrapped_kek_material: The unwrapped binary kek material of a new
                                   key
    :type unwrapped_kek_material:  byte array
    """
    # TODO: Remove entity_type from EntityKey since it is useless.
    # Master keys will not have Entities.
    def __init__(self, entity_type, entity_key_id=None, value_dict=None,
                 parent_kek_material=None, parent_id=None,
                 unwrapped_kek_material=None, unwrapped_dek_material=None):
        self.logger = get_logger(conf=None,
                                 log_route="rotating_keymaster_helpers")
        self.entity_type = entity_type
        self.id = None
        if entity_key_id is None:
            if entity_type == 'Master':
                '''
                The ID for Barbican keys cannot be generated here, since it
                is already set as part of the Barbican Name. If entity_key_id
                is None here, it is an error.
                '''
                raise ValueError(
                    "entity_key_id cannot be None for Master keys")
            key_uuid = None
            if value_dict is not None:
                key_id = value_dict.get(KEY_ID)
                if key_id is not None:
                    self.id = key_id
                    key_uuid = uuid.UUID(key_id)
            if self.id is None:
                key_uuid = uuid.uuid1()
                self.id = str(key_uuid)
            self.created_time = long((key_uuid.get_time() -
                                      0x01b21dd213814000L) * 100 / 1e9)
        else:
            self.id = entity_key_id
            key_uuid = uuid.UUID(entity_key_id)
            self.created_time = long((key_uuid.get_time() -
                                      0x01b21dd213814000L) * 100 / 1e9)
        """
        Parent ID points to the ID of the key of the level above, e.g., for
        object keys, it points to the container key
        """
        self.parent_id = None
        """
        The key material of the KEK.
        """
        self.kek_material = KeyMaterial()
        self.kek_material.unwrapped_bytes = unwrapped_kek_material
        """
        The key material of the DEK, which is passed to the other middleware
        components, e.g., encrypter and decrypter, which encrypt and decrypt
        the actual object data and the object, container (and account)
        metadata. The DEKs cannot be rotated/re-keyed, only the KEKs.
        """
        self.dek_material = KeyMaterial()
        self.dek_material.unwrapped_bytes = unwrapped_dek_material
        if value_dict is not None:
            self.kek_material.b64_encoded_wrapped_bytes = (
                value_dict[WRAPPED_KEK])
            self.dek_material.b64_encoded_wrapped_bytes = (
                value_dict[WRAPPED_DEK])
            self.parent_id = value_dict[PARENT_ID]
            self.iv = base64.b64decode(value_dict[IV])
        elif (parent_kek_material is None or
              parent_id is None or
              unwrapped_kek_material is None or
              unwrapped_dek_material is None):
            raise ValueError('Either value_dict, or all four of '
                             'parent_kek_material (%s), parent_id (%s), '
                             'unwrapped_kek_material (%s), and '
                             'unwrapped_dek_material (%s) shall be '
                             'specified' %
                             (base64.b64encode(parent_kek_material),
                              parent_id,
                              base64.b64encode(unwrapped_kek_material),
                              base64.b64encode(unwrapped_dek_material)))
        else:
            self.kek_material.unwrapped_bytes = unwrapped_kek_material
            self.parent_id = parent_id
            self.kek_material.wrap(parent_kek_material)
            self.dek_material.wrap(unwrapped_kek_material)
            crypto = Crypto()
            self.iv = crypto.create_iv()

    def get_value_dict(self):
        value_dict = dict()
        value_dict[KEY_ID] = self.id
        value_dict[WRAPPED_KEK] = self.kek_material.b64_encoded_wrapped_bytes
        value_dict[WRAPPED_DEK] = self.dek_material.b64_encoded_wrapped_bytes
        value_dict[IV] = base64.b64encode(self.iv)
        if self.parent_id is not None:
            value_dict[PARENT_ID] = self.parent_id
        return value_dict

    def rewrap_kek(self, old_wrapping_key, new_wrapping_key,
                   new_wrapping_key_id):
        if self.kek_material is None:
            raise ValueError("KEK material is none!")
        self.kek_material.unwrap(old_wrapping_key)
        self.kek_material.wrapped_bytes = None
        self.kek_material.b64_encoded_wrapped_bytes = None
        self.kek_material.wrap(new_wrapping_key)
        self.parent_id = new_wrapping_key_id

    def rekey_kek(self, parent_id, parent_kek_material, new_kek_material):
        self.kek_material = KeyMaterial()
        self.kek_material.unwrapped_bytes = new_kek_material
        self.parent_id = parent_id
        self.kek_material.wrap(parent_kek_material)
        self.dek_material.b64_encoded_wrapped_bytes = None
        self.dek_material.wrapped_bytes = None
        self.dek_material.wrap(new_kek_material)


class Entity(object):
    """
    Entity class for holding information about keys and wrapping keys for
    Swift entities (here an Object, Container, Account, or Master).
    """
    VALID_ENTITIES = {'master', 'account', 'container', 'object'}

    def __init__(self, entity_type, name=None):
        self.logger = get_logger(conf=None,
                                 log_route="rotating_keymaster_helpers")
        self.entity_type = entity_type.lower()
        if self.entity_type not in Entity.VALID_ENTITIES:
            raise ValueError("Invalid Entity type: %s" % entity_type)
        self.entity_keys = dict()
        self.name = name
        self.deleted_entity_keys = []

    def get_parent_ids(self):
        parent_ids = set()
        for v in self.entity_keys.itervalues():
            parent_ids.add(v.parent_id)
        return parent_ids

    def get_most_recent_key_by_id(self, key_id):
        """
        Returns the most recent EntityKey of this Entity. For keys not stored
        in Barbican, the most recent EntityKey is determined based on the
        creation time of the EntityKey.

        :param key_id: The id of the most recent EntityKey that we are
                       looking for
        :type key_id:  string

        :return most_recent_kek: the most recent EntityKey of this Entity.
        :rtype most_recent_kek: EntityKey
        """
        most_recent_timestamp = None
        most_recent_key = None

        for v in self.entity_keys.itervalues():
            if v.kek_material is None:
                raise ValueError("Kek material is None!")
            if v.id is None:
                raise ValueError("Key ID is None for %s key" %
                                 v.entity_type)
            if v.parent_id is None:
                raise ValueError("Parent ID is None for %s key" %
                                 v.entity_type)
            if v.created_time is None:
                raise ValueError("Created time not set for %s key %s" %
                                 (v.entity_type, v.id))
            if key_id is not None and key_id != v.id:
                continue
            if ((most_recent_timestamp is not None) and
                    (type(most_recent_timestamp) != type(v.created_time))):
                raise ValueError("Version type mismatch! (" +
                                 type(most_recent_timestamp) +
                                 ", " + type(v.created_time) + ")")
            if ((most_recent_timestamp is None) or
                    (v.created_time > most_recent_timestamp)):
                most_recent_timestamp = v.created_time
                most_recent_key = v
        if most_recent_key is None:
            raise ValueError("most_recent_key is None!")
        if most_recent_key.kek_material is None:
            raise ValueError("kek_material is None for most_recent_key with "
                             "id " + most_recent_key.id)
        return most_recent_key

    def get_most_recent_key_by_parent_id(self, parent_id=None):
        """
        Returns the most recent EntityKey of this Entity. For keys stored in
        Barbican, the most recent EntityKey is determined based on the
        explicitly set version value. For other keys, it is determined based
        on the timestamp of the uuid in the id field.

        :param parent_id: The parent_id of the most recent EntityKey that we
                          are looking for
        :type parent_id:  string

        :return most_recent_kek: the most recent EntityKey of this Entity.
        :rtype most_recent_kek: EntityKey
        """
        most_recent_timestamp = None
        most_recent_key = None

        for v in self.entity_keys.itervalues():
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "Found " +
                            self.entity_type + " kek with id " + v.id)
            if v.kek_material is None:
                raise ValueError("Kek material is None!")
            if v.id is None:
                raise ValueError("Key ID is None for %s key" % v.entity_type)
            if v.created_time is None:
                raise ValueError("Created time not set for %s key %s" %
                                 (v.entity_type, v.id))
            if parent_id is not None and parent_id != v.parent_id:
                continue
            if ((most_recent_timestamp is not None) and
                    (type(most_recent_timestamp) != type(v.created_time))):
                raise ValueError("Version type mismatch! (" +
                                 type(most_recent_timestamp) +
                                 ", " + type(v.created_time) + ")")
            if ((most_recent_timestamp is None) or
                    (v.created_time > most_recent_timestamp)):
                most_recent_timestamp = v.created_time
                most_recent_key = v
        if most_recent_key is None:
            raise ValueError("most_recent_key is None!")
        if most_recent_key.kek_material is None:
            raise ValueError("kek_material is None for most_recent_key with "
                             "id " + most_recent_key.id)
        return most_recent_key

    def get_most_recent_key(self):
        """
        Returns the most recent EntityKey of this Entity. For keys stored in
        Barbican, the most recent EntityKey is determined based on the
        explicitly set version value. For other keys, it is determined based
        on the timestamp of the uuid in the id field.

        :return most_recent_kek: the most recent EntityKey of this Entity.
        :rtype most_recent_kek: EntityKey
        """
        return self.get_most_recent_key_by_parent_id(parent_id=None)

    def get_entitykey_by_id(self, entity_key_id):
        try:
            return self.entity_keys[entity_key_id]
        except KeyError:
            raise ValueError("%s key ID '%s' not found in entity" %
                             (self.entity_type, entity_key_id))

    def dump_meta(self):
        """
        Gets the Entity encryption key information as a dict, where the key
        is the name of the EntityKey, e.g.,
        'X-Account-Sysmeta-Enc-860a724e-1df8-11e7-8303-026f8338c1e5', and the
        value is the json-encoded string representation of the EntityKey value.

        { 'X-Account-Sysmeta-Enc-1111-2222-3333-4444': {
            'key_id': 'key_id_val1',
            'parent_id': 'parent_id_val1',
            'wrapped_kek': 'wrapped_kek_val1',
            'wrapped_dek': 'wrapped_dek_val1' },
          'X-Account-Sysmeta-Enc-5555-6666-7777-8888': {
            'key_id': 'key_id_val2',
            'parent_id': 'parent_id_val2',
            'wrapped_kek': 'wrapped_kek_val2',
            'wrapped_dek': 'wrapped_dek_val2' },
        }

        :return keyrotate_crypto_meta: the entity metadata as a json string,
                                       indexed into dict using entity key name
        :rtype keyrotate_crypto_meta:  dict
        """
        keyrotate_crypto_meta = dict()
        for key_uuid, v in self.entity_keys.iteritems():
            val_dict = v.get_value_dict()
            prefix = self.generate_name_prefix(self.entity_type)
            name = prefix + key_uuid
            keyrotate_crypto_meta[name] = json.dumps(val_dict)
        for key_uuid in self.deleted_entity_keys:
            prefix = self.generate_name_prefix(self.entity_type)
            name = prefix + key_uuid
            keyrotate_crypto_meta[name] = ''
        return keyrotate_crypto_meta

    def add_entity_key(self, entity_key):
        """
        :param entity_key: EntityKey to add to the Entity
        :type  entity_key: EntityKey
        """
        self.entity_keys[entity_key.id] = entity_key

    def del_entity_key(self, entity_key_id):
        del self.entity_keys[entity_key_id]
        self.deleted_entity_keys.append(entity_key_id)

    def generate_name_prefix(self, entity_type):
        prefix = SYSMETA_X + '-' + entity_type.capitalize()
        if entity_type.lower() == SYSMETA_OBJECT.lower():
            prefix = prefix + '-' + SYSMETA_TRANSIENT
        prefix = (prefix + '-' + SYSMETA_SYSMETA + '-' +
                  SYSMETA_ENC_PREFIX + '-')
        return prefix
