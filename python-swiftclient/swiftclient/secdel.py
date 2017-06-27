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

import json
import logging
from swiftclient.service import SwiftError
from castellan import key_manager, options
from castellan.common.credentials import keystone_password
from castellan.common.exception import ManagedObjectNotFoundError
from oslo_config import cfg

logger = logging.getLogger("swiftclient")
SECDEL_LOG_LEVEL_DEBUG = logging.DEBUG
SECDEL_LOG_LEVEL_INFO = logging.INFO
SECDEL_LOG_LEVEL_ERROR = logging.ERROR


def secdel_get_barbican_manager_and_ctxt(output_manager, conf, api_class):
    try:
        # FIXME: Parameters have different names if passed as options
        # to swift-client
        user_domain_name = conf.get('os_user_domain_name')
        if user_domain_name is None:
            user_domain_name = 'Default'
        project_domain_name = conf.get('os_project_domain_name')
        if project_domain_name is None:
            project_domain_name = 'Default'
        ctxt = keystone_password.KeystonePassword(
            username=conf.get('os_username'),
            password=conf.get('os_password'),
            project_name=conf.get('os_project_name'),
            user_domain_name=user_domain_name,
            project_domain_name=project_domain_name,
            user_id=conf.get('os_user_id'),
            user_domain_id=conf.get('os_user_domain_id'),
            trust_id=conf.get('os_trust_id'),
            domain_id=conf.get('os_domain_id'),
            domain_name=conf.get('os_domain_name'),
            project_id=conf.get('os_project_id'),
            project_domain_id=conf.get('os_project_domain_id'),
            reauthenticate=conf.get('reauthenticate'))
        oslo_conf = cfg.ConfigOpts()
        # FIXME: os_auth_url and not auth_endpoint?
        options.set_defaults(
            oslo_conf, auth_endpoint=conf.get('os_auth_url'),
            api_class=conf.get('api_class', api_class)
        )
        options.enable_logging()
        manager = key_manager.API(oslo_conf)
        return manager, ctxt
    except SwiftError as e:
        output_manager.error(e.value)


def secdel_list_barbican_secrets(output_manager, manager, ctxt):
    try:
        root_secrets = manager.list_secrets(
            ctxt, name='swift_root_secret', bits=256, algorithm='aes')
        logger.log(SECDEL_LOG_LEVEL_DEBUG,
                   "Found %d secrets:" % len(root_secrets))
        for k in root_secrets:
            logger.log(SECDEL_LOG_LEVEL_DEBUG, "'%s'" % k)
        return root_secrets
    except SwiftError as e:
        output_manager.error(e.value)


def secdel_create_barbican_secret(output_manager, manager, ctxt):
    try:
        created_id = manager.create_key(
            ctxt, algorithm='aes', length=256, expiration=None,
            name='swift_root_secret')
        logger.log(SECDEL_LOG_LEVEL_DEBUG,
                   "Created new secret with id '%s'" % created_id)
        return created_id
    except SwiftError as e:
        output_manager.error(e.value)


def secdel_delete_barbican_secret(output_manager, manager, ctxt, secret_id):
    try:
        manager.delete(ctxt, secret_id)
        logger.log(SECDEL_LOG_LEVEL_DEBUG,
                   "Deleted secret with id '%s'" % secret_id)
    except SwiftError as e:
        output_manager.error(e.value)


def secdel_list_account(output_manager, swift):
    try:
        stats_parts_gen = swift.list()
        return stats_parts_gen

    except SwiftError as e:
        output_manager.error(e.value)


def secdel_get_account_key_id_by_parent_id(
        output_manager, swift, actual_parent_id):
    try:
        stat_result = swift.stat()
        if not stat_result['success']:
            raise stat_result['error']
        items = stat_result['items']
        headers = stat_result['headers']
        logger.log(SECDEL_LOG_LEVEL_DEBUG, "Result headers type: %s" %
                   type(headers))
        logger.log(SECDEL_LOG_LEVEL_DEBUG, headers)
        logger.log(SECDEL_LOG_LEVEL_DEBUG, "End result headers")
        for k, v in headers.iteritems():
            logger.log(SECDEL_LOG_LEVEL_DEBUG,
                       "Header key: '%s', value: '%s'" %
                       (k, v))
        logger.log(SECDEL_LOG_LEVEL_DEBUG, "End for result headers")
        keys = headers.get('x-account-encryption-keys')
        if keys is None:
            logger.log(SECDEL_LOG_LEVEL_DEBUG, "No encryption keys in headers")
        else:
            keys_list = json.loads(keys)
            logger.log(SECDEL_LOG_LEVEL_DEBUG, type(keys_list))
            logger.log(SECDEL_LOG_LEVEL_DEBUG, keys_list)
            for key in keys_list:
                key_id = key.get('key_id')
                parent_id = key.get('parent_id')
                logger.log(SECDEL_LOG_LEVEL_DEBUG,
                           "Found key with id '%s' and parent id '%s'" %
                           (key_id, parent_id))
                if parent_id == actual_parent_id:
                    logger.log(SECDEL_LOG_LEVEL_DEBUG,
                               "Found key with desired parent")
                    return key_id
                else:
                    logger.log(SECDEL_LOG_LEVEL_DEBUG,
                               "Key does not have desired parent ('%s')" %
                               actual_parent_id)
        return None

    except SwiftError as e:
        output_manager.error(e.value)


def secdel_get_barbican_secret(output_manager, manager, ctxt, secret_id):
    try:
        return manager.get(ctxt, secret_id)
    except SwiftError as e:
        output_manager.error(e.value)
    except ManagedObjectNotFoundError:
        output_manager.error(
            "Root encryption secret not found: '%s'" % secret_id)
    except ValueError:
        output_manager.error(
            "Root encryption secret incorrectly specified: '%s'" % secret_id)
    except Exception as e:
        output_manager.error(e)


def secdel_post(output_manager, swift, container, objects,
                header_key, header_value):
    options = dict()
    secdel_headers = dict()
    secdel_headers[header_key] = header_value
    headers = secdel_headers
    options['header'] = headers
    result = None
    if objects is None:
        result = swift.post(options=options, container=container)
    else:
        results_iterator = swift.post(
            options=options, container=container, objects=objects)
        result = next(results_iterator)
    logger.log(SECDEL_LOG_LEVEL_DEBUG, "result type: %s" % type(result))
    logger.log(SECDEL_LOG_LEVEL_DEBUG, result)


def secdel_rekey(output_manager, swift, container=None, objects=None):
    logger.log(SECDEL_LOG_LEVEL_DEBUG, "ENTER secdel_rekey()")
    secdel_post(output_manager, swift, container, objects, 'Rekey', '')
    logger.log(SECDEL_LOG_LEVEL_DEBUG, "EXIT secdel_rekey()")


def secdel_rewrap(output_manager, swift, container=None, objects=None):
    logger.log(SECDEL_LOG_LEVEL_DEBUG, "ENTER secdel_rekey()")
    secdel_post(output_manager, swift, container, objects, 'Rewrap', '')
    logger.log(SECDEL_LOG_LEVEL_DEBUG, "EXIT secdel_rekey()")


def secdel_purge(output_manager, swift, key_id, container=None, objects=None):
    logger.log(SECDEL_LOG_LEVEL_DEBUG, "ENTER secdel_purge()")
    secdel_post(output_manager, swift, container, objects, 'Purge', key_id)
    logger.log(SECDEL_LOG_LEVEL_DEBUG, "EXIT secdel_purge()")


def secdel_list_container(output_manager, swift, container):
    try:
        stats_parts_gen = swift.list(container=container)
        return stats_parts_gen

    except SwiftError as e:
        output_manager.error(e.value)


def secdel_list_keys(output_manager, swift, container=None, object=None):
    objects = None
    if object is not None:
        objects = [object]
    stat_result = swift.stat(container=container, objects=objects)
    if not stat_result['success']:
        raise stat_result['error']
    items = stat_result['items']
    headers = stat_result['headers']
    logger.log(SECDEL_LOG_LEVEL_DEBUG,
               "Result headers type: %s" % type(headers))
    logger.log(SECDEL_LOG_LEVEL_DEBUG, headers)
    logger.log(SECDEL_LOG_LEVEL_DEBUG, "End result headers")
    for k, v in headers.iteritems():
        logger.log(SECDEL_LOG_LEVEL_DEBUG, "Header key: '%s', value: '%s'" %
                   (k, v))
    encryption_keys = None
    if object is not None:
        encryption_keys = json.loads(headers.get("x-object-encryption-keys"))
    elif container is not None:
        encryption_keys = json.loads(headers.get(
            "x-container-encryption-keys"))
    else:
        encryption_keys = json.loads(headers.get("x-account-encryption-keys"))
    keys = []
    for entity_key in encryption_keys:
        key_id = entity_key.get("key_id")
        keys.append(key_id)
#         parent_key_id = entity_key.get("parent_id")
    logger.log(SECDEL_LOG_LEVEL_DEBUG, "End for result headers")
    return keys


def secdel_exists(output_manager, swift, container, object=None):
    try:
        if container is None:
            raise ValueError("Container is None")
        if '/' in container:
            output_manager.error(
                'WARNING: / in container name; you might have '
                "meant '%s' instead of '%s'." %
                (container.replace('/', ' ', 1), container))
            return
        if object is None:
            logger.log(SECDEL_LOG_LEVEL_DEBUG, "object is None")
            stat_result = swift.stat(container=container)
            if not stat_result['success']:
                logger.log(
                    SECDEL_LOG_LEVEL_DEBUG,
                    "secdel_exists(), stat(container=%s) was not success" %
                    container)
                raise stat_result['error']
            logger.log(SECDEL_LOG_LEVEL_DEBUG,
                       "secdel_exists(), stat(container=%s) was success" %
                       container)
            return True
        else:
            logger.log(SECDEL_LOG_LEVEL_DEBUG, "object is not None")
            objects = [object]
            stat_results = swift.stat(
                container=container, objects=objects)
            for stat_result in stat_results:
                if stat_result["success"]:
                    return True
                else:
                    raise(stat_result["error"])

    except SwiftError as e:
        logger.log(SECDEL_LOG_LEVEL_DEBUG, "secdel_exists() caught error")
        output_manager.error(e.value)
        return False
