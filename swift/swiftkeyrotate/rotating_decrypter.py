# Copyright (c) 2016-2017 OpenStack Foundation
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
from swift import gettext_ as _
from swift.common.swob import HTTPInternalServerError
from swift.common.swob import Request, HTTPException
from swift.common.middleware.crypto.crypto_utils import CRYPTO_KEY_CALLBACK
from swift.common.middleware.crypto.decrypter import Decrypter, \
    DecrypterObjContext, DecrypterContContext
from rotating_keymaster_helpers import SECDEL_LOG_LEVEL_DEBUG, \
    SECDEL_LOG_LEVEL_ERROR, get_header


class RotatingDecrypterObjContext(DecrypterObjContext):
    def __init__(self, decrypter, logger):
        super(RotatingDecrypterObjContext, self).__init__(decrypter, logger)

    def get_keys(self, env, required=None):
        # Get the key(s) from the keymaster
        required = required if required is not None else [self.server_type]
        try:
            fetch_crypto_keys = env.get(CRYPTO_KEY_CALLBACK)
            if fetch_crypto_keys is None:
                identity_status = get_header(env, 'X-Identity-Status')
                user_agent = get_header(env, 'User-Agent')
                if (identity_status is None and
                        user_agent == 'Swift'):
                    self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                                    "No get_keys() callback, but it should be "
                                    "fine for an internal subrequest")
                    return None
                else:
                    self.logger.log(SECDEL_LOG_LEVEL_ERROR,
                                    "No get_keys() callback, and not internal "
                                    "subrequest")
                    raise HTTPInternalServerError(
                        "Unable to retrieve encryption keys.")
        except KeyError:
            self.logger.exception(_('ERROR get_keys() missing callback'))
            raise HTTPInternalServerError(
                "Unable to retrieve encryption keys.")

        try:
            keys = fetch_crypto_keys()
        except Exception as err:  # noqa
            self.logger.exception(_(
                'ERROR get_keys(): from callback: %s') % err)
            raise HTTPInternalServerError(
                "Unable to retrieve encryption keys.")

        for name in required:
            try:
                key = keys[name]
                self.crypto.check_key(key)
                continue
            except KeyError:
                self.logger.exception(_("Missing key for %r") % name)
            except TypeError:
                self.logger.exception(_("Did not get a keys dict"))
            except ValueError as e:
                # don't include the key in any messages!
                self.logger.exception(_("Bad key for %(name)r: %(err)s") %
                                      {'name': name, 'err': e})
            raise HTTPInternalServerError(
                "Unable to retrieve encryption keys.")

        return keys


class RotatingDecrypterContContext(DecrypterContContext):
    def __init__(self, decrypter, logger):
        super(RotatingDecrypterContContext, self).__init__(
            decrypter, logger)

    def get_keys(self, env, required=None):
        # Get the key(s) from the keymaster
        required = required if required is not None else [self.server_type]
        try:
            fetch_crypto_keys = env.get(CRYPTO_KEY_CALLBACK)
            if fetch_crypto_keys is None:
                identity_status = get_header(env, 'X-Identity-Status')
                user_agent = get_header(env, 'User-Agent')
                if (identity_status is None and
                        user_agent == 'Swift'):
                    self.logger.log(SECDEL_LOG_LEVEL_DEBUG,
                                    "No get_keys() callback, but it should be "
                                    "fine for an internal subrequest")
                    return None
                else:
                    self.logger.log(SECDEL_LOG_LEVEL_ERROR,
                                    "No get_keys() callback, and not internal "
                                    "subrequest")
                    raise HTTPInternalServerError(
                        "Unable to retrieve encryption keys.")
        except KeyError:
            self.logger.exception(_('ERROR get_keys() missing callback'))
            raise HTTPInternalServerError(
                "Unable to retrieve encryption keys.")

        try:
            keys = fetch_crypto_keys()
        except Exception as err:  # noqa
            self.logger.exception(_(
                'ERROR get_keys(): from callback: %s') % err)
            raise HTTPInternalServerError(
                "Unable to retrieve encryption keys.")

        for name in required:
            try:
                key = keys[name]
                self.crypto.check_key(key)
                continue
            except KeyError:
                self.logger.exception(_("Missing key for %r") % name)
            except TypeError:
                self.logger.exception(_("Did not get a keys dict"))
            except ValueError as e:
                # don't include the key in any messages!
                self.logger.exception(_("Bad key for %(name)r: %(err)s") %
                                      {'name': name, 'err': e})
            raise HTTPInternalServerError(
                "Unable to retrieve encryption keys.")

        return keys


class RotatingDecrypter(Decrypter):
    """Middleware for decrypting data and user metadata."""

    def __init__(self, app, conf):
        super(RotatingDecrypter, self).__init__(
            app, conf)

    def __call__(self, env, start_response):
        req = Request(env)
        try:
            parts = req.split_path(3, 4, True)
        except ValueError:
            return self.app(env, start_response)

        if parts[3] and req.method == 'GET':
            handler = RotatingDecrypterObjContext(
                self, self.logger).handle_get
        elif parts[3] and req.method == 'HEAD':
            handler = RotatingDecrypterObjContext(
                self, self.logger).handle_head
        elif parts[2] and req.method == 'GET':
            handler = RotatingDecrypterContContext(
                self, self.logger).handle_get
        else:
            # url and/or request verb is not handled by decrypter
            return self.app(env, start_response)

        try:
            return handler(req, start_response)
        except HTTPException as err_resp:
            return err_resp(env, start_response)
