# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

import logging

import requests

from nkr_proxy.exceptions import *
from nkr_proxy.settings import settings


logger = logging.getLogger(__name__)


def http_request(method='get', *args, **kwargs):
    if settings.DEBUG:
        logger.debug('HTTP request begin with data:')
        #logger.debug('args: %r' % args)
        #logger.debug('kwargs: %r' % kwargs)

    try:
        if method == 'get':
            response = getattr(requests, method)(*args, verify=settings.VERIFY_TLS, **kwargs)

        if method == 'post':
            response = getattr(requests, method)(*args, verify=settings.VERIFY_TLS, **kwargs)
            response_headers = response.headers
            logger.debug('Response headers: %s', response_headers)

    except Exception as e:
        logger.exception('HTTP request failed (%s): %s' % (type(e), e))
        raise

    logger.debug('HTTP request completed with code: %d' % response.status_code)

    if response.status_code != 200:
        requested_host = response.request.url[:-len(response.request.path_url)]
        message = '%s: %s' % (requested_host, response.content.decode('utf-8'))

        if response.status_code == 400:
            logger.warning(message)
            raise BadRequest(message)
        elif response.status_code == 401:
            logger.error(message)
            raise Unauthorized(message)
        elif response.status_code == 403:
            logger.error(message)
            raise Forbidden(message)
        elif response.status_code == 404:
            raise NotFound(message)
        else:
            logger.error(message)
            raise ServiceNotAvailable(message)

    return response

