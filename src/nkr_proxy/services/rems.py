# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

import logging

from nkr_proxy.exceptions import *
from nkr_proxy.settings import settings
from nkr_proxy.utils import http_request


logger = logging.getLogger(__name__)

REMS_EVENT_ACCEPTED = 'application.event/accepted'
REMS_EVENT_CLOSED = 'application.event/closed'
REMS_EVENT_REJECTED = 'application.event/rejected'
REMS_EVENT_REVOKED = 'application.event/revoked'

REMS_STATE_DRAFT = 'application.state/draft'
REMS_STATE_SUBMITTED = 'application.state/submitted'
REMS_STATE_ACCEPTED = 'application.state/accepted'
REMS_STATE_CLOSED = 'application.state/closed'
REMS_STATE_REJECTED = 'application.state/rejected'
REMS_STATE_REVOKED = 'application.state/revoked'


def close_rems_application(user_id, application_id, comment, close_as_user=None):
    """
    Close a single application in REMS by application_id.
    If parameter close_as_user is provided, attempt to close the application as that user,
    otherwise close the application as the owner (user_id).
    """
    logger.info('Closing REMS application id %d for user: %s...' % (application_id, user_id))

    headers = {
        'Accept': 'application/json',
        'x-rems-api-key': settings.REMS_API_KEY,
        'x-rems-user-id': close_as_user or user_id,
    }

    payload = {
        'application-id': application_id,
        'comment': comment,
    }

    try:
        response = http_request(
            'https://%s/api/applications/close' % settings.REMS_HOST,
            method='post',
            json=payload,
            headers=headers
        )
    except Exception as e:
        logger.exception('Could not close application %d for user %s: %s' % (application_id, user_id, str(e)))
        return False

    if response.json()['success'] == False:
        logger.info(
            'Could not close application %d for user %s: %s' \
            % (application_id, user_id, str(response.json()['errors']))
        )
        return False

    logger.info('Closed application %d for user %s' % (application_id, user_id))

    return True


def get_rems_entitlements(user_id, full_entitlements=False):
    """
    Return current active entitlements of a user from REMS.

    By default returns only a list of the resource ids of the entitlements,
    but parameter full_entitlements can be used to return the full response as-is.
    """
    logger.debug('Retrieving REMS entitlements for user: %s...' % user_id)

    headers = {
        'Accept': 'application/json',
        'x-rems-api-key': settings.REMS_API_KEY,
        'x-rems-user-id': user_id,
    }

    try:
        response = http_request('https://%s/api/entitlements' % settings.REMS_HOST, headers=headers)
    except:
        raise ServiceNotAvailable()

    entitlements = response.json()

    if settings.DEBUG:
        logger.debug('Received %d entitlements for user %s' % (len(entitlements), user_id))
        logger.debug('Entitlements:')
        for ent in entitlements:
            logger.debug('- %s' % ent['resource'])

    if full_entitlements:
        return entitlements

    # only care about the resource identifiers from the response
    return [ ent['resource'] for ent in entitlements ]
