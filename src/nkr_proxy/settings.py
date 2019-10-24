# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

import logging
import os

from nkr_proxy.exceptions import ConfigurationError


logger = logging.getLogger(__name__)


def get_boolean_conf_param(env_var):

    env_var_value = os.environ.get(env_var, None)

    if env_var_value in ('1', 'true'):
        return True
    elif env_var_value in ('0', 'false'):
        return False

    raise ConfigurationError(
        '%s value must be one of: 1, 0, "true", "false". Given value was: %r' % (env_var, env_var_value)
    )


def get_list_conf_param(env_var):
    env_var_value = os.environ.get(env_var, None)
    if env_var_value:
        return set(env_var_value.split(','))
    return []


class Settings():

    # try to find these vars from environment variables,
    # which should have been sourced from config.sh and test_config.sh
    NKR_PROXY_CONF_VARS = (
        'NKR_ENV',
        'DEBUG',
        'VERIFY_TLS',
        'INDEX_URL',
        'INDEX_IP_LIST',
        'INDEX_MAIN_API',
        'INDEX_HOSTNAME',
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

    INDEX_HEADERS = {}

    INDEX_HOSTS = []

    def __init__(self):

        for env_var in self.NKR_PROXY_CONF_VARS:

            if env_var in ('INDEX_ALLOWED_APIS', 'INDEX_IP_LIST'):
                env_var_value = get_list_conf_param(env_var)
            elif env_var in ('DEBUG', 'VERIFY_TLS'):
                env_var_value = get_boolean_conf_param(env_var)
            else:
                env_var_value = os.environ.get(env_var, None)

            setattr(self, env_var, env_var_value)

        self._set_index_hosts()

    def _set_index_hosts(self):
        """
        self.INDEX_HOSTS will be the list of hosts that the proxy uses to connect to the index,
        even if there is only one entry. Before request is tried, the list is shuffled, and
        then the list is tried in order.

        Either of the following must be defined in ENV variables:
        - INDEX_IP_LIST
        - INDEX_MAIN_API
        - INDEX_HOSTNAME
        OR
        - INDEX_URL
        """
        if self.INDEX_IP_LIST and self.INDEX_MAIN_API and self.INDEX_HOSTNAME:

            logger.debug('Using conf vars INDEX_IP_LIST, INDEX_MAIN_API, and INDEX_HOSTNAME to access index')

            protocol = 'http' if self.NKR_ENV == 'local_development' else 'https'

            self.INDEX_HOSTS = [ '%s://%s%s' % (protocol, ip, self.INDEX_MAIN_API) for ip  in self.INDEX_IP_LIST ]

            self.INDEX_HEADERS = { 'Host': self.INDEX_HOSTNAME }

        elif self.INDEX_URL is not None:
            logger.debug('Using conf var INDEX_URL to access index')
            self.INDEX_HOSTS = [ self.INDEX_URL ]
        else:
            raise ConfigurationError(
                'Must define either INDEX_URL in config, or all of the following: '
                'INDEX_IP_LIST, INDEX_MAIN_API, INDEX_HOSTNAME'
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
