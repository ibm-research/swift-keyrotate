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
import logging

from castellan import key_manager, options
from castellan.common.credentials import keystone_token
from oslo_config import cfg
from swift.common.swob import Request, HTTPException
from swift.common.utils import readconf, get_logger
from rotating_keymaster_helpers import SECDEL_LOG_LEVEL_DEBUG
from rotating_keymaster_context import RotatingKeyMasterContext
from swift.common.utils import register_swift_info

# Time in seconds to keep root secrets cached in the keymaster.
# Set to 0 to disable caching.
# TODO: Non-zero currently caches forever.
ROOT_SECRET_CACHE_TIME = 0


class RotatingKeyMaster(object):
    """Middleware for managing encryption key hierarchies.
    """

    def __init__(self, app, conf):
        # The keys for the _user_root_secrets dict are the IDs of the root
        # secrets in the KMS, and the values are the unwrapped, raw key
        # material bytes.
        self._user_root_secrets = dict()
        self.logger = get_logger(conf, log_route="rotating_keymaster")
        # Only log critical errors from rotating_keymaster_helpers
        logging.getLogger(
            'rotating_keymaster_helpers').setLevel(logging.CRITICAL)
        self.app = app
        self.conf = conf
        self.keymaster_config_path = conf.get('keymaster_config_path')

    def get_latest_user_root_secret_and_id(self, account, user_token):
        """
        Retrieve the user's latest root encryption secret from an external key
        management system using Castellan.

        :param account: the name of the account
        :type account: string

        :param user_token: the keystone token of the user from the request
        :type user_token: string

        :return: a tuple containing the binary bytes of the latest encryption
                 root secret, and the id of the latest root encryption secret
        :rtype: (bytearray, string)
        """
        conf = self.conf
        if self.keymaster_config_path is not None:
            if any(opt in conf for opt in ('key_id',)):
                raise ValueError('keymaster_config_path is set, but there '
                                 'are other config options specified!')
            conf = readconf(self.keymaster_config_path, 'rotating_keymaster')
        user_ctxt = keystone_token.KeystoneToken(token=user_token)
        oslo_conf = cfg.ConfigOpts()
        options.set_defaults(
            oslo_conf, auth_endpoint=conf.get('auth_endpoint'),
            api_class=conf.get('api_class')
        )
        options.enable_logging()
        manager = key_manager.API(oslo_conf)
        # Get the latest key from Barbican. If no keymanager class has been
        # specified (using 'api_class'), or the keymaster does not have a
        # 'get_latest_key()' method, an exception will be raised.
        latest_user_root_secret_id, key = manager.get_latest_key(
            user_ctxt, bits=256, algorithm='aes', name='swift_root_secret')
        self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                        "ID of latest user root secret is %s" %
                        latest_user_root_secret_id)
        if latest_user_root_secret_id is None or key is None:
            return None, None
        user_root_secrets = self._user_root_secrets.get(account)
        if user_root_secrets is None:
            user_root_secrets = dict()
        user_root_secrets[latest_user_root_secret_id] = key.get_encoded()
        self._user_root_secrets[account] = user_root_secrets
        return key.get_encoded(), latest_user_root_secret_id

    def get_user_root_secret_by_id(self, account, user_token, key_id):
        """
        Retrieve the user's root encryption secret with the specified ID from
        an external key management system using Castellan.

        :param account: the name of the account
        :type account: string

        :param user_token: the keystone token of the user from the request
        :type user_token: string

        :param key_id: the ID of the user's root encryption secret to retrieve

        :return: the binary bytes of the user's root encryption secret with the
                 specified ID
        :rtype: bytearray
        """
        user_root_secrets = self._user_root_secrets.get(account)
        if user_root_secrets is None:
            user_root_secrets = dict()
        else:
            encoded_key = user_root_secrets.get(key_id)
            if ROOT_SECRET_CACHE_TIME > 0:
                if encoded_key is not None:
                    return encoded_key
        conf = self.conf
        if self.keymaster_config_path is not None:
            if any(opt in conf for opt in ('key_id',)):
                raise ValueError('keymaster_config_path is set, but there '
                                 'are other config options specified!')
            conf = readconf(self.keymaster_config_path, 'rotating_keymaster')
        user_ctxt = keystone_token.KeystoneToken(token=user_token)
        oslo_conf = cfg.ConfigOpts()
        options.set_defaults(
            oslo_conf, auth_endpoint=conf.get('auth_endpoint'),
            api_class=conf.get('api_class')
        )
        options.enable_logging()
        manager = key_manager.API(oslo_conf)
        # Get the latest key from Barbican. If no keymanager class has been
        # specified (using 'api_class'), or the keymaster does not have a
        # 'get_latest_key()' method, an exception will be raised.
        key = manager.get(user_ctxt, key_id)
        if key is None:
            raise ValueError("Could not find user '%s' with key_id '%s'" %
                             (account, key_id))
        user_root_secrets[key_id] = key.get_encoded()
        self._user_root_secrets[account] = user_root_secrets
        return key.get_encoded()

    def __call__(self, env, start_response):
        req = Request(env)

        try:
            parts = req.split_path(2, 4, True)
        except ValueError:
            return self.app(env, start_response)

        self.logger.log(
            SECDEL_LOG_LEVEL_DEBUG,
            "RotatingKeyMaster: Operation: %s, acc: %s, cont: %s, obj: %s" %
            (req.method, parts[1], parts[2], parts[3]))
        # handle only those request methods that may require keys
        if req.method in ('PUT', 'POST', 'GET', 'HEAD'):
            self.logger.log(SECDEL_LOG_LEVEL_DEBUG, "Creating km_context")
            km_context = RotatingKeyMasterContext(self, *parts[1:])
            try:
                self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                                "Calling handle_request")
                return km_context.handle_request(req, start_response, env)
            except HTTPException as err_resp:
                return err_resp(env, start_response)

        # anything else
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    register_swift_info('rotating_keymaster')

    def rotating_keymaster_filter(app):
        return RotatingKeyMaster(app, conf)

    return rotating_keymaster_filter
