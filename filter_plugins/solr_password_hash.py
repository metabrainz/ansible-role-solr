import base64
import hashlib

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_bytes, to_text
from ansible.utils.encrypt import random_salt

def solr_password_hash(password, salt=None):
    """Return a text string suitable for use as a Solr authentication hash"""
    if salt is None:
        salt = random_salt(length=32)

    salt_bytes = to_bytes(salt, errors='surrogate_or_strict')
    if len(salt_bytes) != 32:
        raise AnsibleFilterError('salt must be exactly 32 bytes long')

    h = hashlib.new('sha256')
    h.update(salt_bytes)
    h.update(to_bytes(password, errors='strict'))
    pw_hash = h.digest()

    h = hashlib.new('sha256')
    h.update(pw_hash)
    pw_hash = h.digest()
    return '{0} {1}'.format(
        to_text(base64.b64encode(pw_hash)),
        to_text(base64.b64encode(salt_bytes))
    )

class FilterModule(object):

    def filters(self):
        return {
            'solr_password_hash': solr_password_hash,
        }
