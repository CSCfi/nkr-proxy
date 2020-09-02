# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

import logging
import os
import sys

from dotenv import load_dotenv

from nkr_proxy.exceptions import ConfigurationError


logger = logging.getLogger(__name__)


def executing_tests():
    """
    When automated tests are being executed, the module 'pytest' is loaded.
    """
    return 'pytest' in sys.modules


def get_boolean_conf_param(env_var):

    env_var_value = os.environ.get(env_var, None)

    if env_var_value in ('1', 'true'):
        return True
    elif env_var_value in ('0', 'false'):
        return False

    raise ConfigurationError(
        '%s value must be one of: 1, 0, "true", "false". Given value was: %r' % (env_var, env_var_value)
    )


def get_int_conf_param(env_var):
    env_var_value = os.environ.get(env_var, None)
    if env_var_value:
        return int(env_var_value)
    return None


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
        'INDEX_HOSTS',
        'INDEX_MAIN_API',
        'INDEX_NAME',
        'INDEX_USERNAME',
        'INDEX_PASSWORD',
        'INDEX_ALLOWED_APIS',
        'LEVEL_RESTRICTION_FIELD',
        'DOCUMENT_UNIQUE_ID_FIELD',
        'METADATA_LEVEL_10_RESOURCE_ID',
        'LOG_LEVEL',
        'REMS_API_KEY',
        'REMS_HOST',
        'REMS_REJECTER_BOT_USER',
        'CACHE_HOST',
        'CACHE_PORT',
        'CACHE_PASSWORD',
        'CACHE_DB',
        'CACHE_SOCKET_TIMEOUT',
        'SESSION_TIMEOUT_LIMIT',
        'SESSION_TIMEOUT_LIMIT_LONG',
        'SESSION_CLEANUP_MAX_TIME',
        'REMS_SESSION_CLOSE_MESSAGE',
        'REMS_SESSION_CLOSE_MESSAGE_ACTIVE',
        'REMS_SESSION_CLOSE_USER',
        'REMS_LOGOUT_MESSAGE',
        'CRON_SESSION_EXPIRE_LOG',
        'MAX_AMOUNT_OF_REQUESTS_SHORT_PERIOD',
        'MAX_AMOUNT_OF_REQUESTS_LONG_PERIOD',
        'EXCLUDE_REQUESTS_WITH_FIELD_PARAM',
        'INCLUDE_REQUESTS_WITH_FIELD_PARAM',
        'REQ_TIME_DIFFERENCE_LOWER_BOUND',
        'MAIL_SERVER',
        'MAIL_PORT',
        'MAIL_USE_TLS',
        'MAIL_USE_SSL',
        'MAIL_DEFAULT_SENDER',
        'MAIL_MAX_EMAILS',
        'MAIL_RECIPIENT',
    )

    INDEX_HEADERS = {}

    INDEX_HOSTS = []

    def __init__(self):

        if not executing_tests():
            # reload environment variables from file, since systemd only reloads env
            # variables upon "restart", not "reload"
            load_dotenv(
                dotenv_path=os.environ.get('CONFIG_PATH'),
                override=True
            )

        for env_var in self.NKR_PROXY_CONF_VARS:

            if env_var in ('INDEX_ALLOWED_APIS', 'INDEX_HOSTS'):
                env_var_value = get_list_conf_param(env_var)
            elif env_var in ('DEBUG', 'VERIFY_TLS'):
                env_var_value = get_boolean_conf_param(env_var)
            elif env_var in ('CACHE_PORT', 'SESSION_TIMEOUT_LIMIT', 'SESSION_CLEANUP_MAX_TIME'):
                env_var_value = get_int_conf_param(env_var)
            else:
                env_var_value = os.environ.get(env_var, None)

            setattr(self, env_var, env_var_value)

        protocol = 'http' if self.NKR_ENV == 'local_development' else 'https'
        self.INDEX_HOSTS = [ '%s://%s%s' % (protocol, host, self.INDEX_MAIN_API) for host  in self.INDEX_HOSTS ]

    def __repr__(self):
        vars_list = []
        for var in self.NKR_PROXY_CONF_VARS:
            vars_list.append('%s=%r' % (var, getattr(self, var, None)))
        return '\n'.join(vars_list)
        
try:
    settings = Settings()
except:
    logger.exception('Error during Settings initialization')
    raise
