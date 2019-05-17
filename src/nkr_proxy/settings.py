import logging
import os

from nkr_proxy.exceptions import ConfigurationError


logger = logging.getLogger(__name__)


class Settings():

    NKR_PROXY_CONF_VARS = (
        'DEBUG',
        'INDEX_URL',
        'INDEX_NAME',
        'INDEX_USERNAME',
        'INDEX_PASSWORD',
        'LEVEL_RESTRICTION_FIELD',
        'DOCUMENT_UNIQUE_ID_FIELD',
        'LOG_LEVEL',
        'REMS_API_KEY',
        'REMS_URL',
    )

    def __init__(self):

        for env_var in self.NKR_PROXY_CONF_VARS:
            setattr(self, env_var, os.environ.get(env_var, None))

        if self.DEBUG in ('1', 'true'):
            self.DEBUG = True
        elif self.DEBUG in ('0', 'false'):
            self.DEBUG = False
        else:
            raise ConfigurationError(
                'DEBUG value must be one of: 1, 0, "true", "false". Given value was: %r' % self.DEBUG
            )

    def __repr__(self):
        vars_list = []
        for var in self.NKR_PROXY_CONF_VARS:
            vars_list.append('%s=%r' % (var, getattr(self, var, None)))
        return '\n'.join(vars_list)
        
try:
    settings = Settings()
except:
    logging.exception('Error during Settings initialization')
    raise
