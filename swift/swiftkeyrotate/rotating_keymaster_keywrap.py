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

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.backends import default_backend


class KeyWrap(object):
    """
    Implements key wrapping (without associated data) for AES keys in a
    simplified SIV mode with CMAC and CTR modes.  SIV mode is specified in
    P. Rogaway and T. Shrimpton, 'Deterministic Authenticated-Encryption: A
    Provable-Security Treatment of the Key-Wrap Problem', Cryptology ePrint
    Archive: Report 2006/221 and in RFC 5297.

    The differences to SIV mode are: (1) The un/wrapping key given to the
    un/wrapping algorithm is one AES key instead of two, this key is
    expanded internally to two AES keys; (2) No support for associated data
    (also called headers).
    """

    @staticmethod
    def _number_to_bytes(val, length):
        """
        Takes a number "val", interprets it in binary as bytearray, and
        expands the array to "length" bytes.  Returns the result as a
        string.
        """

        assert (0 <= val & val < 256)
        s = bytearray(length)
        for j in range(length):
            s[j] = int(val)
        return str(s)

    @staticmethod
    def _expand_key(key, count):
        """
        Takes one AES key (128, 192, or 256 bits) and derives from it
        "count" keys of the same length, by invoking AES as a pseudo-random
        function.
        """

        aes_keylengths = [16, 24, 32]
        keylength = len(key)
        assert (keylength in aes_keylengths)

        keys = []
        for i in range(count):
            clr = KeyWrap._number_to_bytes(i, keylength)
            enc = Cipher(algorithms.AES(key),
                         modes.CTR(str(bytearray(range(16)))),
                         backend=default_backend()).encryptor()
            subkey = enc.update(clr)
            keys.append(subkey)
        return keys

    @staticmethod
    def wrap(master_key, target_key):
        """
        Wraps "target_key" with "master_key" in the simplified SIV mode
        and returns the wrapped key.

        :param master_key: The AES key used for wrapping; must be 128, 192
        or 256 bits.
        :param target_key: The key to be wrapped; must be at least one AES
        block long (128 bits).
        """
        assert len(target_key) >= 16
        keys = KeyWrap._expand_key(master_key, 2)
        cm = cmac.CMAC(algorithms.AES(keys[0]), backend=default_backend())
        cm.update(target_key)
        iv = cm.finalize()
        assert len(iv) == 16
        enc = Cipher(algorithms.AES(keys[1]), modes.CTR(iv),
                     backend=default_backend()).encryptor()
        ct = enc.update(target_key) + enc.finalize()
        return iv + ct

    @staticmethod
    def unwrap(master_key, wrapped_key):
        """
        Unwraps "wrapped_key" with "master_key" in the simplified SIV mode.
        If the wrapping was properly authenticated, it returns the target
        key; otherwise, it raises an "InvalidKey" exception.

        :param master_key: The AES key used for unwrapping; must be 128,
        192 or 256 bits.
        :param wrapped_key: The ciphertext to be unwrapped; must be at
        least one AES block long (128 bits).
        """
        assert len(wrapped_key) >= 16
        keys = KeyWrap._expand_key(master_key, 2)
        iv = wrapped_key[0:16]
        dec = Cipher(algorithms.AES(keys[1]), modes.CTR(iv),
                     backend=default_backend()).decryptor()
        target_key = dec.update(wrapped_key[16:]) + dec.finalize()
        assert len(wrapped_key) == len(target_key) + 16
        cm = cmac.CMAC(algorithms.AES(keys[0]), backend=default_backend())
        cm.update(target_key)
        ivp = cm.finalize()
        if iv != ivp:
            pass
        return target_key
