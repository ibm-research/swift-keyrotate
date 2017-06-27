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
import os
import uuid
import json
import copy

from swift.common.http import is_success
from swift.common.middleware.crypto.crypto_utils import CRYPTO_KEY_CALLBACK
from swift.common.middleware.crypto.keymaster import KeyMasterContext
from swift.common.middleware.crypto.crypto_utils import Crypto
from swift.common.swob import Request, HTTPNotFound, HTTPForbidden, \
    HTTPInternalServerError
from swift.common.utils import get_logger
from swift.common.wsgi import make_subrequest
from swift.proxy.controllers.base import get_account_info, \
    get_container_info, get_object_info
from rotating_keymaster_helpers import Entity, EntityKey, \
    SECDEL_LOG_LEVEL_INFO, SECDEL_LOG_LEVEL_DEBUG, SECDEL_LOG_LEVEL_ERROR, \
    REKEY_POST_HEADER, PURGE_POST_HEADER, SYSMETA_X, SYSMETA_ACCOUNT, \
    SYSMETA_CONTAINER, SYSMETA_OBJECT, SYSMETA_TRANSIENT, SYSMETA_SYSMETA, \
    SYSMETA_ENC_PREFIX, REWRAP_POST_HEADER, get_header


class RotatingKeyMasterContext(KeyMasterContext):
    """
    Generate new and/or retrieve existing keys required for encrypting or
    decrypting object body keys, as well as container and object user metadata.

    Random 256-bit AES key encryption keys are generated and stored in the
    account, container, and object metadata. The key encryption keys are
    wrapped with their parent key encryption keys, and the account key
    encryption key is wrapped with a root encryption key stored using the
    user's credentials in a Barbican key management system.
    """
    def __init__(self, keymaster, account, container, obj):
        """
        :param keymaster: a Keymaster instance
        :param account: account name
        :param container: container name
        :param obj: object name
        """
        super(RotatingKeyMasterContext, self).__init__(keymaster, account,
                                                       container, obj)
        self.keys = None
        self._account_entity = None
        self._container_entity = None
        self._object_entity = None
        self._user_token = None
        self._latest_user_root_secret_id = None
        self._env = None
        self.logger = get_logger(keymaster.conf,
                                 log_route="rotating_keymaster_context")

    def fetch_crypto_keys(self, *args, **kwargs):
        """Callback function to provide keys to encrypter and decrypter.
        """
        return self.keys

    def _get_entities(self):
        """Gets the entities for the request.

        If the path of an entity is not specified, None is returned for that
        Entity.
        """
        env_copy = copy.copy(self._env)
        # Do not try to perform any encryption on any subrequests
        # TODO: This does not seem to have any impact
        env_copy['swift.crypto.override'] = True
        container_entity = None
        object_entity = None
        if self.obj:
            object_entity = self._get_object_entity(env_copy)
        if self.container:
            container_entity = self._get_container_entity(env_copy)
        account_entity = self._get_account_entity(env_copy)
        return account_entity, container_entity, object_entity

    def _create_and_post_new_entity_key(self, account, entity_type,
                                        root_key_id, root_key_material,
                                        account_entity=None,
                                        container_entity=None,
                                        object_entity=None):
        new_entity = self._create_new_entity(account, entity_type,
                                             root_key_id,
                                             root_key_material,
                                             account_entity, container_entity)
        self._post_entity_metadata(new_entity)
        return new_entity

    def _create_bogus_entity(self, entity_type):
        """Create a bogus entity for requests when no keys are available.

        Handling regular client requests, e.g., a PUT of an object, results
        in multiple internal subrequests being generated, e.g., HEAD requests
        on the account and container. These internal subrequests are performed
        with admin credentials, and the user token is not passed in. These
        requests are used to e.g., retrieve the encryption keys from the
        account/container/object metadata, and no keys can be provided for the
        request (chicken and egg problem). For these requests, bogus entities
        are passed in, since the encrypter and decrypter middleware require
        some keys to be available. Since for these requests we only care about
        the system metadata (which is not encrypted using these keys), we pass
        dummy keys in the bogus entities.

        :param entity_type: type of entity to be created
        :type entity_type: string

        :return: Entity of the requested type with bogus key ID and material
        :rtype: Entity
        """
        entity = Entity(entity_type.lower())
        entity_key = EntityKey(
            entity_type=entity_type.lower(),
            entity_key_id='00000000-0000-0000-0000-000000000000',
            value_dict=None,
            parent_kek_material=str(bytearray(32)),
            parent_id='00000000-0000-0000-0000-000000000000',
            unwrapped_kek_material=str(bytearray(32)),
            unwrapped_dek_material=str(bytearray(32)))
        entity.add_entity_key(entity_key)
        return entity

    def _create_new_entity(self, account, entity_type, root_key_id,
                           root_key_material,
                           account_entity=None,
                           container_entity=None):
        """Create a new entity, containing new entity keys.

        :param account: the name of the account under which the entity exists
        :param entity_type: the type of entity to create
        :param root_key_id: the ID of the latest root encryption key to use
        :param root_key_material: the key material of the root encryption key
        :param account_entity: the parent account entity in the path (for
                               containers and objects)
        :param container_entity: the parent container entity in the path (for
                                 objects)
        """
        if root_key_id is None:
            raise ValueError('root_key_id is None')
        else:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                            "Creating new entity with root key id: '%s'" %
                            root_key_id)
        wrapping_key_id = None
        wrapping_key_material = None
        if entity_type == SYSMETA_ACCOUNT:
            wrapping_key_id = root_key_id
            wrapping_key_material = root_key_material
        elif entity_type == SYSMETA_CONTAINER:
            account_entity_key = account_entity.get_most_recent_key()
            account_entity_key, _, _ = self._unwrap_entity_keys(
                account, account_entity_key)
            wrapping_key_id = account_entity_key.id
            wrapping_key_material = (
                account_entity_key.kek_material.unwrapped_bytes)
        elif entity_type == SYSMETA_OBJECT:
            container_entity_key = container_entity.get_most_recent_key()
            account_entity_key = account_entity.get_entitykey_by_id(
                container_entity_key.parent_id)
            _, container_entity_key, _ = self._unwrap_entity_keys(
                account, account_entity_key, container_entity_key)
            wrapping_key_id = container_entity_key.id
            wrapping_key_material = (
                container_entity_key.kek_material.unwrapped_bytes)
        else:
            raise ValueError("Unsupported Entity type: %s" % entity_type)
        if wrapping_key_id is None:
            raise ValueError("wrapping_key_id is still None")
        if wrapping_key_material is None:
            raise ValueError("wrapping_key_material is still None")
        new_entity = Entity(entity_type.lower())
        new_entity_key = self._create_entity_key(
            new_entity, wrapping_key_id, wrapping_key_material)
        self.logger.log(
            SECDEL_LOG_LEVEL_DEBUG,
            "Created new entity key for %s with id %s" %
            (entity_type, new_entity_key.id))
        return new_entity

    def _unwrap_entity_keys(self, account, account_entity_key,
                            container_entity_key=None, object_entity_key=None):
        """
        Unwrap the entity keys provided, using the provided master key
        material, and thereafter the key encryption keys (KEKs) in the entity
        keys.

        :return: Tuple of unwrapped account, container, and object entity keys,
                 where the container and object entity keys are None if none
                 were provided in the input.
        :rtype:  Tuple of EntityKey objects, where the keys have been unwrapped
        """
        if account_entity_key is None:
            self.logger.log(SECDEL_LOG_LEVEL_ERROR,
                            "Account '%s' entity key not found, "
                            "unable to decrypt" % account)
            raise HTTPNotFound("Account key missing, unable to decrypt")
        master_key_material = self.keymaster.get_user_root_secret_by_id(
            account, self._user_token, account_entity_key.parent_id)
        account_entity_key.kek_material.unwrap(master_key_material)
        account_entity_key.dek_material.unwrap(
            account_entity_key.kek_material.unwrapped_bytes)
        if container_entity_key is None:
            return account_entity_key, None, None
        container_entity_key.kek_material.unwrap(
            account_entity_key.kek_material.unwrapped_bytes)
        container_entity_key.dek_material.unwrap(
            container_entity_key.kek_material.unwrapped_bytes)
        if object_entity_key is None:
            return account_entity_key, container_entity_key, None
        object_entity_key.kek_material.unwrap(
            container_entity_key.kek_material.unwrapped_bytes)
        object_entity_key.dek_material.unwrap(
            object_entity_key.kek_material.unwrapped_bytes)
        return account_entity_key, container_entity_key, object_entity_key

    def _get_account_entity(self, env):
        '''
        Get the account entity from the account metadata. The account entity
        contains zero or more entity keys, representing the encryption keys
        for the account.

        :returns entity: Entity with parsed EntityKeys for the account
        :rtype: Entity
        '''
        account_info = get_account_info(env, self.app)
        sys_meta = account_info.get(SYSMETA_SYSMETA.lower())
        if sys_meta is None:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "sys_meta is None")
            return None
        return self._get_entity_from_metadata(
            SYSMETA_ACCOUNT.lower(), sys_meta)

    def _get_container_entity(self, env):
        '''
        Get the container entity from the container metadata. The container
        entity contains zero or more entity keys, representing the encryption
        keys for the container.

        :returns entity: Entity with parsed EntityKeys for the container
        :rtype: Entity
        '''
        container_info = get_container_info(env, self.app)
        sys_meta = container_info.get(SYSMETA_SYSMETA.lower())
        if sys_meta is None:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "sys_meta is None")
            return None
        return self._get_entity_from_metadata(
            SYSMETA_CONTAINER.lower(), sys_meta)

    def _get_object_entity(self, env):
        '''
        Get the object entity from the object metadata. The object entity
        contains zero or more entity keys, representing the encryption keys for
        the object.

        :returns entity: Entity with parsed EntityKeys for the object
        :rtype: Entity
        '''
        object_info = get_object_info(env, self.app)
        sys_meta = object_info.get("%s_%s" % (SYSMETA_TRANSIENT.lower(),
                                              SYSMETA_SYSMETA.lower()))
        if sys_meta is None:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "sys_meta is None")
            return None
        return self._get_entity_from_metadata(SYSMETA_OBJECT.lower(), sys_meta)

    def _get_entity_from_metadata(self, entity_type, sys_meta):
        entity = Entity(entity_type)
        for k, v in sys_meta.iteritems():
            if k.lower().startswith(SYSMETA_ENC_PREFIX.lower() + '-'):
                value_dict = json.loads(v)
                entity_name_uuid = k[len(SYSMETA_ENC_PREFIX) + 1:]
                # Try parsing the UUID part of the name
                uuid.UUID(entity_name_uuid)
                entity_key = EntityKey(entity_type, entity_key_id=None,
                                       value_dict=value_dict)
                entity.add_entity_key(entity_key)
        return entity

    def _post_entity_metadata(self, entity):
        '''
        Store new and existing metadata for the entity using a POST request.

        If the entity is None, any existing metadata is erased.
        '''
        subreq = Request(self._env)
        self._add_entity_metadata_to_req(subreq, entity)
        self._make_post_subrequest(subreq, entity)

    def _add_entity_metadata_to_req(self, subreq, entity):
        if entity is None:
            raise ValueError("Entity to post metadata for cannot be None")
        if len(entity.entity_keys) == 0:
            # Erase any existing entity metadata
            header_name_prefix = (
                "%s-%s-%s-%s" % (SYSMETA_X, entity.entity_type,
                                 SYSMETA_SYSMETA, SYSMETA_ENC_PREFIX))
            if entity.entity_type == SYSMETA_OBJECT:
                header_name_prefix = (
                    "%s-%s-%s-%s-%s" % (SYSMETA_X, entity.entity_type,
                                        SYSMETA_TRANSIENT, SYSMETA_SYSMETA,
                                        SYSMETA_ENC_PREFIX))
            for k in subreq.headers.iterkeys():
                if k.lower().startswith(header_name_prefix.lower()):
                    subreq.headers[k] = ''
        else:
            # Store new entity metadata
            new_meta = entity.dump_meta()
            subreq.headers.update(new_meta)

    def _make_post_subrequest(self, subreq, entity):
        path = None
        if entity.entity_type.lower() == SYSMETA_ACCOUNT.lower():
            # The path may be /a/c even if the entity is account, in case this
            # is the first operation on an account, with the request containing
            # the user token. In this case, a POST on the account is performed,
            # even though the path of the original request also contains
            # container.
            version, acc, _ = subreq.split_path(1, 3, True)
            path = '/'.join(['', version, acc])
        elif entity.entity_type.lower() == SYSMETA_CONTAINER.lower():
            version, acc, cont = subreq.split_path(1, 3, False)
            path = '/'.join(['', version, acc, cont])
        elif entity.entity_type.lower() == SYSMETA_OBJECT.lower():
            version, acc, cont, obj = subreq.split_path(1, 4, False)
            path = '/'.join(['', version, acc, cont, obj])
        else:
            raise ValueError("Invalid entity type: %s" % entity.entity_type)
        con_req = make_subrequest(
            self._env, method='POST', path=path,
            headers=subreq.headers,
            agent=('%(orig)s ' + 'KM_Update_Meta'))

        con_resp = con_req.get_response(self.app)
        if not is_success(con_resp.status_int):
            raise ValueError("Error updating metadata: %d" %
                             con_resp.status_int)

    def _create_entity_key(self, entity, wrapping_key_id,
                           wrapping_key_material,
                           unwrapped_dek_material_bytes=None):
        """
        Create entity key for encryption.

        :param entity: the entity for which the entity key is being created
        :type entity:  Entity

        :param wrapping_key_id: the ID of the parent wrapping key
        :type wrapping_key_id:  string

        :param wrapping_key_material: The unwrapped bytes of the wrapping key
        :type wrapping_key_material:  byte array

        :returns: The EntityKey of the new key to use
        :rtype: EntityKey
        """
        crypto = Crypto()
        binary_kek = crypto.create_random_key()
        binary_dek = unwrapped_dek_material_bytes
        if binary_dek is None:
            binary_dek = crypto.create_random_key()
        binary_parent_kek = wrapping_key_material
        entity_type = entity.entity_type
        entity_key = EntityKey(entity_type, entity_key_id=None,
                               value_dict=None,
                               parent_kek_material=binary_parent_kek,
                               parent_id=wrapping_key_id,
                               unwrapped_kek_material=binary_kek,
                               unwrapped_dek_material=binary_dek)
        entity.add_entity_key(entity_key)
        return entity_key

    def handle_request(self, req, start_response, env):
        self._env = env
        req.environ[CRYPTO_KEY_CALLBACK] = self.fetch_crypto_keys

        self.logger.log(
            SECDEL_LOG_LEVEL_DEBUG,
            "ROT: Operation: %s, acc: %s, cont: %s, obj: %s" %
            (req.method, self.account, self.container, self.obj))
        entity_keys = dict()
        path = None
        account_path = os.path.join(os.sep, self.account)
        req_entity_type = SYSMETA_ACCOUNT
        if self.obj:
            req_entity_type = SYSMETA_OBJECT
        elif self.container:
            req_entity_type = SYSMETA_CONTAINER
        elif self.account is None:
            raise ValueError("No account specified")
        # Check if we have the necessary keys, and if not, generate them
        # and, if necessary, store them using a POST subrequest.
        # Only the 'last' part of the request may require a new key, i.e.,
        # if a HEAD is performed e.g., on a container, then we can assume
        # that the account already has a key stored in its metadata.
        self._user_token = get_header(self._env, 'X-Auth-Token')
        is_internal_subrequest = False
        if self._user_token is None:
            identity_status = get_header(self._env, 'X-Identity-Status')
            user_agent = get_header(self._env, 'User-Agent')
            if (identity_status == 'Invalid' and
                    user_agent == 'Swift'):
                self.logger.log(
                    SECDEL_LOG_LEVEL_DEBUG,
                    "Internal subrequest, hopefully we do not need user_token")
                is_internal_subrequest = True
            else:
                raise ValueError("Unable to retrieve user token from header")
        latest_user_root_secret_id = None
        latest_user_root_secret_material = None
        try:
            account_entity, container_entity, object_entity = (
                self._get_entities())
        except ValueError as err:
            # A ValueError may be raised e.g., if a key UUID is malformed.
            error_response = HTTPInternalServerError(
                body=str(err), content_type='text/plain')
            return error_response(self._env, start_response)
        if req_entity_type == SYSMETA_ACCOUNT:
            if (account_entity is None or
                    len(account_entity.entity_keys) == 0):
                # Operating on Account, but no Account entity keys exist
                if req.method in ('PUT', 'POST'):
                    (latest_user_root_secret_material,
                     latest_user_root_secret_id) = (
                         self.keymaster.get_latest_user_root_secret_and_id(
                             self.account, self._user_token))
                    if (latest_user_root_secret_material is None or
                            latest_user_root_secret_id is None):
                        error_response = HTTPForbidden(
                            body="No root encryption secret found",
                            content_type='text/plain')
                        return error_response(self._env, start_response)
                    account_entity = self._create_new_entity(
                        self.account, SYSMETA_ACCOUNT,
                        latest_user_root_secret_id,
                        latest_user_root_secret_material)
                    self._add_entity_metadata_to_req(req, account_entity)
                elif self._user_token is not None:
                    # When using user master keys, a first PUT does not end up
                    # here, since the HEAD request does not have the user
                    # token, and therefore no master wrapping key is known to
                    # the proxy.
                    if (latest_user_root_secret_id is None or
                            latest_user_root_secret_material is None):
                        (latest_user_root_secret_material,
                         latest_user_root_secret_id) = (
                             self.keymaster.get_latest_user_root_secret_and_id(
                                 self.account, self._user_token))
                        if (latest_user_root_secret_material is None or
                                latest_user_root_secret_id is None):
                            error_response = HTTPForbidden(
                                body="No root encryption secret found",
                                content_type='text/plain')
                            return error_response(self._env, start_response)
                    account_entity = self._create_and_post_new_entity_key(
                        self.account,
                        SYSMETA_ACCOUNT, latest_user_root_secret_id,
                        latest_user_root_secret_material)
            entity_keys[SYSMETA_ACCOUNT.lower()] = (
                account_entity.get_most_recent_key())
        if req_entity_type == SYSMETA_CONTAINER:
            path = os.path.join(account_path, self.container)
            latest_user_root_secret_id = None
            latest_user_root_secret_material = None
            if (account_entity is None or
                    len(account_entity.entity_keys) == 0):
                if req.method == 'PUT':
                    # This path can be reached when trying to PUT the first
                    # object into swift, when there is not yet any entity key
                    # in the account.
                    (latest_user_root_secret_material,
                     latest_user_root_secret_id) = (
                         self.keymaster.get_latest_user_root_secret_and_id(
                             self.account, self._user_token))
                    if (latest_user_root_secret_material is None or
                            latest_user_root_secret_id is None):
                        error_response = HTTPForbidden(
                            body="No root encryption secret found",
                            content_type='text/plain')
                        return error_response(self._env, start_response)
                    account_entity = self._create_new_entity(
                        self.account, SYSMETA_ACCOUNT,
                        latest_user_root_secret_id,
                        latest_user_root_secret_material)
                    self._post_entity_metadata(account_entity)
                else:
                    # On a fresh swift install, this path can be reached
                    # if the first request from an account is e.g., a GET on a
                    # (obviously) non-existent container.
                    self.logger.log(
                        SECDEL_LOG_LEVEL_DEBUG,
                        "Operating on container '/%s/%s', but account does "
                        "not have an entity or entity keys" %
                        (self.account, self.container))
                    return self._handle_request_with_bogus_keys(
                        start_response, req, path)
            if (container_entity is None or
                    len(container_entity.entity_keys) == 0):
                # Operating on Container, but no Container entity keys exist
                if req.method in ('PUT', 'POST'):
                    if (latest_user_root_secret_id is None or
                            latest_user_root_secret_material is None):
                        (latest_user_root_secret_material,
                         latest_user_root_secret_id) = (
                             self.keymaster.get_latest_user_root_secret_and_id(
                                 self.account, self._user_token))
                        if (latest_user_root_secret_material is None or
                                latest_user_root_secret_id is None):
                            error_response = HTTPForbidden(
                                body="No root encryption secret found",
                                content_type='text/plain')
                            return error_response(self._env, start_response)
                    container_entity = self._create_new_entity(
                        self.account, SYSMETA_CONTAINER,
                        latest_user_root_secret_id,
                        latest_user_root_secret_material,
                        account_entity, container_entity)
                    self._add_entity_metadata_to_req(req, container_entity)
                else:
                    self.logger.log(
                        SECDEL_LOG_LEVEL_DEBUG,
                        "GETting or HEADing on non-existent Container")
                    return self._handle_request_with_bogus_keys(start_response,
                                                                req, path)
            try:
                entity_keys[SYSMETA_CONTAINER.lower()] = (
                    container_entity.get_most_recent_key())
                entity_keys[SYSMETA_ACCOUNT.lower()] = (
                    account_entity.get_entitykey_by_id(
                        entity_keys[SYSMETA_CONTAINER.lower()].parent_id))
            except ValueError as err:
                self.logger.log(
                    SECDEL_LOG_LEVEL_DEBUG,
                    "Error retrieving key(s): %s" % err)
                self.logger.log(
                    SECDEL_LOG_LEVEL_DEBUG,
                    "Operation was '%s', is_internal_subrequest: %s" %
                    (req.method, is_internal_subrequest))
                if ((req.method in ('DELETE', 'HEAD')) or
                        (is_internal_subrequest)):
                    return self._handle_request_with_bogus_keys(
                        start_response, req, path)
                error_response = HTTPForbidden(
                    body="Securely deleted", content_type='text/plain')
                return error_response(self._env, start_response)
        if req_entity_type == SYSMETA_OBJECT:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "Operating on Object")
            path = os.path.join(account_path, self.container)
            path = os.path.join(path, self.obj)
            if (account_entity is None or
                    len(account_entity.entity_keys) == 0):
                self.logger.log(
                    SECDEL_LOG_LEVEL_DEBUG,
                    "Operating on object '/%s/%s/%s', but account does not "
                    "have an entity or entity keys" %
                    (self.account, self.container, self.obj))
                return self._handle_request_with_bogus_keys(
                    start_response, req, path)
            if (container_entity is None or
                    len(container_entity.entity_keys) == 0):
                # This might happen if someone tries to e.g., download an
                # object from a container that does not exist.
                self.logger.log(
                    SECDEL_LOG_LEVEL_DEBUG,
                    "Operating on object '/%s/%s/%s', but container does not "
                    "have an entity or entity keys" %
                    (self.account, self.container, self.obj))
                return self._handle_request_with_bogus_keys(
                    start_response, req, path)
            if ((object_entity is None or len(object_entity.entity_keys) == 0)
                    and req.method in ('GET', 'HEAD')):
                self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                                "GETting or HEADing on new Object /%s/%s/%s" %
                                (self.account, self.container, self.obj))
                self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                                "Providing bogus keys")
                return self._handle_request_with_bogus_keys(start_response,
                                                            req, path)
            else:
                if ((object_entity is None) or
                        (len(object_entity.entity_keys) == 0) or
                        req.method in ('PUT')):
                    # Operating on Object, but no Object entity keys exist
                    # If rePUTting an existing object, we generate new keys,
                    # instead of just re-adding the existing key metadata to
                    # the object metadata that will be recreated.
                    if req.method in ('PUT', 'POST'):
                        self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                                        "PUTting or POSTing on Object")
                        if (latest_user_root_secret_id is None or
                                latest_user_root_secret_material is None):
                            (latest_user_root_secret_material,
                             latest_user_root_secret_id) = (
                                 self.keymaster.
                                 get_latest_user_root_secret_and_id(
                                     self.account, self._user_token))
                            if (latest_user_root_secret_material is None or
                                    latest_user_root_secret_id is None):
                                error_response = HTTPForbidden(
                                    body="No root encryption secret found",
                                    content_type='text/plain')
                                return error_response(self._env,
                                                      start_response)
                        object_entity = self._create_new_entity(
                            self.account,
                            SYSMETA_OBJECT, latest_user_root_secret_id,
                            latest_user_root_secret_material,
                            account_entity, container_entity)
                        self._add_entity_metadata_to_req(req,
                                                         object_entity)
                entity_keys[SYSMETA_OBJECT.lower()] = (
                    object_entity.get_most_recent_key())
                try:
                    entity_keys[SYSMETA_CONTAINER.lower()] = (
                        container_entity.get_entitykey_by_id(
                            entity_keys[SYSMETA_OBJECT.lower()].parent_id))
                    entity_keys[SYSMETA_ACCOUNT.lower()] = (
                        account_entity.get_entitykey_by_id(
                            entity_keys[SYSMETA_CONTAINER.lower()].parent_id))
                except ValueError as err:
                    self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                    "Error retrieving key(s): %s" % err)
                    self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                                    "Operation was '%s', "
                                    "is_internal_subrequest: %s" %
                                    (req.method, is_internal_subrequest))
                    if ((req.method in ('DELETE', 'HEAD')) or
                            (is_internal_subrequest)):
                        return self._handle_request_with_bogus_keys(
                            start_response, req, path)
                    error_response = HTTPForbidden(
                        body="Securely deleted", content_type='text/plain')
                    return error_response(self._env, start_response)
        if self._user_token is not None:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "Unwrapping entity keys")
            self._unwrap_entity_keys(self.account,
                                     entity_keys.get(SYSMETA_ACCOUNT.lower()),
                                     entity_keys.get(
                                         SYSMETA_CONTAINER.lower()),
                                     entity_keys.get(SYSMETA_OBJECT.lower()))
        elif is_internal_subrequest:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                            "Internal subrequest with no user_token, unable "
                            "to unwrap so providing bogus keys")
            return self._handle_request_with_bogus_keys(start_response,
                                                        req, path)
        else:
            raise ValueError("Unable to unwrap keys, user_token is None")
        self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "Adding DEKs to self.keys")
        self.keys = dict()
        for k, v in entity_keys.iteritems():
            dek_material_bytes = v.dek_material.unwrapped_bytes
            if dek_material_bytes is None:
                raise ValueError(
                    "DEK material unwrapped bytes is none for %s" % k)
            self.keys[k] = dek_material_bytes

        self.keys['id'] = {'v': '2', 'path': path}

        purge_key_id = req.headers.get(PURGE_POST_HEADER)
        if purge_key_id is not None:
            self._perform_purge(PURGE_POST_HEADER, req, purge_key_id,
                                req_entity_type, entity_keys,
                                account_entity, container_entity,
                                object_entity)
        else:
            rewrap_parent_id = req.headers.get(REWRAP_POST_HEADER)
            rekey_action = req.headers.get(REKEY_POST_HEADER)
            if ((rewrap_parent_id is not None) and
                    (rekey_action is not None)):
                error_response = HTTPForbidden(
                    body=("Rekey and Rewrap cannot be performed in the "
                          "same request"), content_type='text/plain')
                return error_response(self._env, start_response)
            if rewrap_parent_id is not None:
                self._perform_rotation(REWRAP_POST_HEADER, req,
                                       rewrap_parent_id, req_entity_type,
                                       entity_keys, account_entity,
                                       container_entity, object_entity,
                                       start_response)
            if rekey_action is not None:
                self._perform_rotation(REKEY_POST_HEADER, req,
                                       "", req_entity_type,
                                       entity_keys, account_entity,
                                       container_entity, object_entity,
                                       start_response)

        resp = self._app_call(req.environ)
        start_response(self._response_status, self._response_headers,
                       self._response_exc_info)

        stat_entity = None
        if req_entity_type == SYSMETA_ACCOUNT:
            stat_entity = account_entity
        elif req_entity_type == SYSMETA_CONTAINER:
            stat_entity = container_entity
        elif req_entity_type == SYSMETA_OBJECT:
            stat_entity = object_entity
        stat_keys = list()
        for v in stat_entity.entity_keys.itervalues():
            stat_key = dict()
            stat_key['key_id'] = v.id
            stat_key['parent_id'] = v.parent_id
            stat_keys.append(stat_key)
        stat_keys_json = json.dumps(stat_keys)
        self._response_headers.append(('X-' + req_entity_type +
                                       '-Encryption-Keys', stat_keys_json))

        return resp

    def _handle_request_with_bogus_keys(self, start_response, req, path):
        self.keys = dict()
        self.keys[SYSMETA_OBJECT.lower()] = str(bytearray(32))
        self.keys[SYSMETA_CONTAINER.lower()] = str(bytearray(32))
        self.keys[SYSMETA_ACCOUNT.lower()] = str(bytearray(32))
        self.keys['id'] = {'v': '2', 'path': path}
        resp = self._app_call(req.environ)
        start_response(self._response_status, self._response_headers,
                       self._response_exc_info)
        return resp

    def _unwrap_entity_key(self, entity_key, account_entity, container_entity,
                           object_entity, account):
        object_entity_key = None
        container_entity_key = None
        account_entity_key = None
        if entity_key.entity_type == SYSMETA_OBJECT.lower():
            object_entity_key = entity_key
        elif entity_key.entity_type == SYSMETA_CONTAINER.lower():
            container_entity_key = entity_key
        elif entity_key.entity_type == SYSMETA_ACCOUNT.lower():
            account_entity_key = entity_key
        if object_entity_key is not None:
            container_entity_key = container_entity.get_entitykey_by_id(
                object_entity_key.parent_id)
        if container_entity_key is not None:
            account_entity_key = account_entity.get_entitykey_by_id(
                container_entity_key.parent_id)
        return self._unwrap_entity_keys(account,
                                        account_entity_key,
                                        container_entity_key,
                                        object_entity_key)

    def _get_and_unwrap_hierarchy(self, entity_type, entity_key_id):
        account_entity_key_id = None
        container_entity_key = None
        container_entity_key_id = None
        object_entity_key = None
        object_entity_key_id = None
        if entity_type == SYSMETA_OBJECT:
            object_entity_key_id = entity_key_id
        elif entity_type == SYSMETA_CONTAINER:
            container_entity_key_id = entity_key_id
        elif entity_type == SYSMETA_ACCOUNT:
            account_entity_key_id = entity_key_id
        if object_entity_key_id is not None:
            object_entity_key = self._object_entity.get_entitykey_by_id(
                object_entity_key_id)
            container_entity_key_id = object_entity_key.parent_id
        if container_entity_key_id is not None:
            container_entity_key = self._container_entity.get_entitykey_by_id(
                container_entity_key_id)
            account_entity_key_id = container_entity_key.parent_id
        if account_entity_key_id is None:
            raise ValueError("Account entity key is None")
        account_entity_key = self._account_entity.get_entitykey_by_id(
            account_entity_key_id)
        return self._unwrap_entity_keys(self.account,
                                        account_entity_key,
                                        container_entity_key,
                                        object_entity_key)

    def _perform_rotation(self, action, req, new_parent_id,
                          req_entity_type, entity_keys, account_entity,
                          container_entity, object_entity,
                          start_response):
        self._account_entity = account_entity
        self._container_entity = container_entity
        self._object_entity = object_entity
        if action not in (REWRAP_POST_HEADER, REKEY_POST_HEADER):
            raise ValueError("Unrecognized key rotation action: %s" % action)
        if "" != new_parent_id:
            self.logger.log(SECDEL_LOG_LEVEL_INFO,
                            "Rewrapping %s with client-specified parent "
                            "key '%s'" % (req_entity_type, new_parent_id))
        if req_entity_type == SYSMETA_ACCOUNT:
            if "" == new_parent_id:
                _, new_parent_id = (
                    self.keymaster.get_latest_user_root_secret_and_id(
                        self.account, self._user_token))
                if new_parent_id is None:
                    error_response = HTTPForbidden(
                        body="No root encryption secret found",
                        content_type='text/plain')
                    return error_response(self._env, start_response)
            entity_key = entity_keys.get(SYSMETA_ACCOUNT.lower())
            current_parent_id = entity_key.parent_id
            if (new_parent_id == current_parent_id and
                    action == REWRAP_POST_HEADER):
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "%s already wrapped with parent key id %s" %
                                (req_entity_type, current_parent_id))
                return
            current_parent_key_material = (
                self.keymaster.get_user_root_secret_by_id(self.account,
                                                          self._user_token,
                                                          current_parent_id))
            new_parent_key_material = (
                self.keymaster.get_user_root_secret_by_id(self.account,
                                                          self._user_token,
                                                          new_parent_id))
            if action == REWRAP_POST_HEADER:
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "Rewrapping %s '%s' with latest parent key "
                                "id '%s'" %
                                (req_entity_type, self.account, new_parent_id))
                entity_key.rewrap_kek(current_parent_key_material,
                                      new_parent_key_material, new_parent_id)
                account_entity.add_entity_key(entity_key)
            elif action == REKEY_POST_HEADER:
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "Rekeying %s '%s' and wrapping with latest "
                                "parent key id '%s'" %
                                (req_entity_type, self.account, new_parent_id))
                unwrapped_dek_material_bytes = (
                    entity_key.dek_material.unwrapped_bytes)
                if unwrapped_dek_material_bytes is None:
                    raise ValueError("Unwrapped DEK material bytes is None")
                self._create_entity_key(account_entity, new_parent_id,
                                        new_parent_key_material,
                                        unwrapped_dek_material_bytes)
            self._add_entity_metadata_to_req(req,
                                             account_entity)
        elif req_entity_type == SYSMETA_CONTAINER:
            if "" == new_parent_id:
                new_parent_id = account_entity.get_most_recent_key().id
            entity_key = entity_keys.get(SYSMETA_CONTAINER.lower())
            current_parent_id = entity_key.parent_id
            if (new_parent_id == current_parent_id and
                    action == REWRAP_POST_HEADER):
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "%s already wrapped with parent key id %s" %
                                (req_entity_type, current_parent_id))
                return
            current_parent_entity_key = account_entity.get_entitykey_by_id(
                current_parent_id)
            current_parent_entity_key, _, _ = self._unwrap_entity_key(
                current_parent_entity_key, account_entity, None, None,
                self.account)
            if current_parent_entity_key is None:
                raise ValueError("current_parent_entity_key is None")
            current_parent_entity_key_kek_material = (
                current_parent_entity_key.kek_material)
            if current_parent_entity_key_kek_material is None:
                raise ValueError(
                    "current_parent_entity_key_kek_material is None")
            current_parent_key_material = (
                current_parent_entity_key_kek_material.unwrapped_bytes)
            if current_parent_key_material is None:
                raise ValueError("current_parent_key_material is None")
            new_parent_entity_key = account_entity.get_entitykey_by_id(
                new_parent_id)
            new_parent_entity_key, _, _ = self._unwrap_entity_key(
                new_parent_entity_key, account_entity, None, None,
                self.account)
            if new_parent_entity_key is None:
                raise ValueError("new_parent_entity_key is None")
            new_parent_entity_key_kek_material = (
                new_parent_entity_key.kek_material)
            if new_parent_entity_key_kek_material is None:
                raise ValueError("new_parent_entity_key_kek_material is None")
            new_parent_key_material = (
                new_parent_entity_key_kek_material.unwrapped_bytes)
            if new_parent_key_material is None:
                raise ValueError("new_parent_key_material is None")
            if action == REWRAP_POST_HEADER:
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "Rewrapping %s '%s' with latest parent key "
                                "id '%s'" %
                                (req_entity_type, self.container,
                                 new_parent_id))
                entity_key.rewrap_kek(current_parent_key_material,
                                      new_parent_key_material, new_parent_id)
                container_entity.add_entity_key(entity_key)
            elif action == REKEY_POST_HEADER:
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "Rekeying %s '%s' and wrapping with latest "
                                "parent key id '%s'" %
                                (req_entity_type, self.container,
                                 new_parent_id))
                unwrapped_dek_material_bytes = (
                    entity_key.dek_material.unwrapped_bytes)
                if unwrapped_dek_material_bytes is None:
                    raise ValueError("Unwrapped DEK material bytes is None")
                self._create_entity_key(container_entity, new_parent_id,
                                        new_parent_key_material,
                                        unwrapped_dek_material_bytes)
            self._add_entity_metadata_to_req(req,
                                             container_entity)
        elif req_entity_type == SYSMETA_OBJECT:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                            "performing rotation on object, new_parent_id: %s"
                            % new_parent_id)
            if "" == new_parent_id:
                new_parent_id = container_entity.get_most_recent_key().id
            entity_key = entity_keys.get(SYSMETA_OBJECT.lower())
            current_parent_id = entity_key.parent_id
            if new_parent_id == current_parent_id:
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "%s already wrapped with parent key id %s" %
                                (req_entity_type, current_parent_id))
                return
            if (new_parent_id == current_parent_id and
                    action == REWRAP_POST_HEADER):
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "%s already wrapped with parent key id %s" %
                                (req_entity_type, current_parent_id))
                return
            self._get_and_unwrap_hierarchy(SYSMETA_CONTAINER,
                                           current_parent_id)
            self._get_and_unwrap_hierarchy(SYSMETA_CONTAINER, new_parent_id)
            current_parent_key_material = container_entity.get_entitykey_by_id(
                current_parent_id).kek_material.unwrapped_bytes
            new_parent_key_material = container_entity.get_entitykey_by_id(
                new_parent_id).kek_material.unwrapped_bytes
            if current_parent_key_material is None:
                raise ValueError("Key material of current parent key with id "
                                 "'%s' is None" % current_parent_id)
            if new_parent_key_material is None:
                raise ValueError("Key material of new parent key with id "
                                 "'%s' is None" % new_parent_id)
            if action == REWRAP_POST_HEADER:
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "Rewrapping %s '%s' with latest parent key "
                                "id '%s'" %
                                (req_entity_type, self.obj, new_parent_id))
                entity_key.rewrap_kek(current_parent_key_material,
                                      new_parent_key_material, new_parent_id)
                object_entity.add_entity_key(entity_key)
            elif action == REKEY_POST_HEADER:
                self.logger.log(SECDEL_LOG_LEVEL_INFO,
                                "Rekeying %s '%s' and wrapping with latest "
                                "parent key id '%s'" %
                                (req_entity_type, self.obj, new_parent_id))
                unwrapped_dek_material_bytes = (
                    entity_key.dek_material.unwrapped_bytes)
                if unwrapped_dek_material_bytes is None:
                    raise ValueError("Unwrapped DEK material bytes is None")
                self._create_entity_key(object_entity, new_parent_id,
                                        new_parent_key_material,
                                        unwrapped_dek_material_bytes)
            self._add_entity_metadata_to_req(req, object_entity)
        else:
            raise ValueError("Unsupported entity type: %s" % req_entity_type)
        del req.headers[action]

    def _perform_purge(self, action, req, key_id_to_purge,
                       req_entity_type, entity_keys, account_entity,
                       container_entity, object_entity):
        if self.obj is not None:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                            "Purging object key %s" % key_id_to_purge)
            object_entity.del_entity_key(key_id_to_purge)
            self._add_entity_metadata_to_req(req, object_entity)
        elif self.container is not None:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                            "Purging container key %s" % key_id_to_purge)
            container_entity.del_entity_key(key_id_to_purge)
            self._add_entity_metadata_to_req(req,
                                             container_entity)
        elif self.account is not None:
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                            "Purging account key %s" % key_id_to_purge)
            account_entity.del_entity_key(key_id_to_purge)
            self._add_entity_metadata_to_req(req,
                                             account_entity)
            header_key = (SYSMETA_X + '-' +
                          SYSMETA_ACCOUNT + '-' +
                          SYSMETA_SYSMETA + '-' +
                          SYSMETA_ENC_PREFIX + '-' +
                          key_id_to_purge)
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                            "Setting empty value for header key '%s'" %
                            header_key)
            req.headers[header_key] = ''
