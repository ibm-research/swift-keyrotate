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

from oslo_log import log as logging

from castellan.common import exception
from castellan.key_manager.barbican_key_manager import BarbicanKeyManager
from barbicanclient import exceptions as barbican_exceptions

LOG = logging.getLogger(__name__)
LIST_LIMIT = 10


class KeyrotateKeyManager(BarbicanKeyManager):
    """Castellan key manager that extends the BarbicanKeyManager and allows
    retrieving the latest key with given parameters from Barbican.
    """

    def __init__(self, configuration):
        super(KeyrotateKeyManager, self).__init__(configuration)

    def _is_current_key_latest(self, previous_secret, previous_secret_id,
                               current_secret, current_secret_id):
        """Compares the current secret to the previous secret, and returns
        true if the current secret is the latest, false if the previous secret
        is more recent.

        The comparison is done first according to the creation time - if the
        creation time is equal, the comparison is done according to the ID of
        the keys.
        """
        if previous_secret is None:
            return True
        if current_secret.created > previous_secret.created:
            return True
        if current_secret.created == previous_secret.created:
            if current_secret_id > previous_secret_id:
                return True
        return False

    def get_latest_key(self, context, mode=None, algorithm=None, bits=0,
                       name=None):
        """
        Retrieve the user's latest root encryption secret from an external key
        management system using Castellan.

        :param context: the user context for authentication
        :param user_token: the mode of the key to look for
        :param algorithm: the algorithm of the key to look for
        :param bits: the bitlength of the key to look for
        :param name: the name of the key to look for

        :return: a tuple containing the id of the latest root key, and the
                 castellan object representation of the key
        :rtype: (string, castellan object)
        """
        barbican_client = self._get_barbican_client(context)
        latest_secret = None
        latest_secret_id = None
        offset = 0
        more = True

        try:
            while more:
                # List all keys that match the requirements
                found = barbican_client.secrets.list(limit=LIST_LIMIT,
                                                     offset=offset,
                                                     name=name,
                                                     algorithm=algorithm,
                                                     mode=mode,
                                                     bits=bits)
                # No (more) results
                if found is None:
                    break
                # At least one result
                if len(found) > 0:
                    for s in found:
                        secret = self._get_castellan_object(s)
                        secret_id = s.secret_ref.rpartition('/')[-1]
                        # Check if the key is the most latest one
                        if self._is_current_key_latest(latest_secret,
                                                       latest_secret_id,
                                                       secret,
                                                       secret_id):
                            latest_secret = secret
                            latest_secret_id = secret_id
                # If there were less than LIST_LIMIT results, we have reached
                # the last page of results.
                if len(found) < LIST_LIMIT:
                    break
                # Otherwise, continue with the next page of results.
                offset += LIST_LIMIT

            return latest_secret_id, latest_secret
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            LOG.error("Error listing keys: %s", e)
            raise exception.KeyManagerError(reason=e)
