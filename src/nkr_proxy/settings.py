# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

import logging
import os

from nkr_proxy.exceptions import ConfigurationError


logger = logging.getLogger(__name__)


class Settings():

    # try to find these vars from environment variables,
    # which should have been sourced from config.sh and test_config.sh
    NKR_PROXY_CONF_VARS = (
        'NKR_ENV',
        'DEBUG',
        'INDEX_URL',
        'INDEX_NAME',
        'INDEX_USERNAME',
        'INDEX_PASSWORD',
        'INDEX_ALLOWED_APIS',
        'LEVEL_RESTRICTION_FIELD',
        'DOCUMENT_UNIQUE_ID_FIELD',
        'METADATA_LEVEL_10_RESOURCE_ID',
        'LOG_LEVEL',
        'REMS_API_KEY',
        'REMS_URL',
    )

    def __init__(self):

        for env_var in self.NKR_PROXY_CONF_VARS:

            env_var_value = os.environ.get(env_var, None)

            if env_var == 'INDEX_ALLOWED_APIS':
                env_var_value = set(env_var_value.split(','))

            setattr(self, env_var, env_var_value)

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
