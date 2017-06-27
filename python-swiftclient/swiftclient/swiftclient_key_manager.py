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
from castellan.i18n import _LE

LOG = logging.getLogger(__name__)
LIST_LIMIT = 10


class SwiftClientKeyManager(BarbicanKeyManager):

    def __init__(self, configuration):
        super(SwiftClientKeyManager, self).__init__(configuration)

    def list_secrets(self, context, mode=None, algorithm=None, bits=0,
                     name=None):
        """List matching secret from Barbican.
        """
        barbican_client = self._get_barbican_client(context)
        found_secrets = list()
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
                        secret_id = s.secret_ref.rpartition('/')[-1]
                        found_secrets.append(secret_id)
                # If there were less than LIST_LIMIT results, we have reached
                # the last page of results.
                if len(found) < LIST_LIMIT:
                    break
                # Otherwise, continue with the next page of results.
                offset += LIST_LIMIT

            return found_secrets
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            LOG.error(_LE("Error listing keys: %s"), e)
            raise exception.KeyManagerError(reason=e)
