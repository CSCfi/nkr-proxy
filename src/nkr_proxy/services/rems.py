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


def check_user_blacklisted(user_id, resource_id):
    """
    Check from REMS /api/blacklist if given user is currently blacklisted for a given resource.
    User "blacklist status" needs to be checked from this API, instead of relying on application
    status, since user being removed from the blacklist is not reflected on past applications.

    Note: The REMS "logged-in" role is not enough for this API (doing the query as the applicant,
    which is provided in parameter user_id). Instead, his API needs one of the following REMS
    roles for user in header x-rems-user-id:
    - handler
    - owner
    - reporter role
    -> using REMS_REJECTER_BOT_USER, since that user can access the API
    """
    logger.info('Checking blacklist status for user: %s...' % user_id)

    headers = {
        'Accept': 'application/json',
        'x-rems-api-key': settings.REMS_API_KEY,
        'x-rems-user-id': settings.REMS_REJECTER_BOT_USER,
    }

    try:
        response = http_request(
            'https://%s/api/blacklist' % settings.REMS_HOST,
            data={ 'user': user_id, 'resource': resource_id },
            method='get',
            headers=headers
        )
    except Exception as e:
        logger.exception('Could not retrieve blacklist info for user %s: %s' % (user_id, str(e)))
        # do not assume user is blacklisted if fetch failed. in worst case,
        # user tries to make a new application, and is immediately rejected by REMS
        # if user actually was blacklisted.
        return { 'blacklisted': False }

    # blacklist entries list only contains entries for requested resource, so if there
    # is even one hit, we can determine user is blacklisted. note: query should return
    # entries only for selected user, but iterating list and verifying anyway.
    for entry in response.json():
        if entry.get('blacklist/user', {}).get('userid') == user_id:
            if entry.get('blacklist/resource', {}).get('resource/ext-id') == resource_id:

                logger.info('User %s is blacklisted for resource %s' % (user_id, resource_id))

                return {
                    'blacklisted': True,
                    'date': entry.get('blacklist/added-at', '-')
                }

    logger.info('User %s is not blacklisted for resource %s' % (user_id, resource_id))

    return { 'blacklisted': False }


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


def get_all_rems_applications(application_state):
    """
    Get all applications in requested state.

    The applications are retrieved as user REMS_REJECTER_BOT_USER, since it is a handler,
    and has access to all applications. The application is closed as the applicant user.
    """
    logger.debug('Getting all applications in state: %s...' % application_state)

    headers = {
        'Accept': 'application/json',
        'x-rems-api-key': settings.REMS_API_KEY,
        'x-rems-user-id': settings.REMS_REJECTER_BOT_USER
    }

    try:
        response = http_request(
            'https://%s/api/applications?query=state:%s' % (settings.REMS_HOST, application_state),
            headers=headers
        )
    except:
        raise ServiceNotAvailable()

    return response.json()


def get_rems_application_close_info(application):
    """
    Extract information about the closing-conditions the latest REMS application:
    - state: REMS state value
    - comment: a comment from the closing user, if any, that was given as reason for closing the application
    - custom_state: a custom state value that can be passed to the client so it knows why user has lost access.
      possible values are:
        - 'logout-closed':          closed due to user logging out
        - 'session-expired-closed': closed due to user's inactivity
        - 'manual-closed':          a REMS approver manually closed the application
        - 'manual-rejected':        a REMS approver manually rejected the application
        - 'manual-revoked':         a REMS approver manually closed the application using blacklist
        - 'automatic-rejected':     REMS rejecter-bot automatically rejected the application
        - 'unknown-closed':         some other, as-of-yet unknown case

    Note! Even if last application state is 'automatic-rejected' or 'manual-revoked', which implies
    user was blacklisted on that application, it is still possible that the user was later
    removed from blacklist.
    """
    if application['application/state'] == REMS_STATE_SUBMITTED:
        # currently there is a tiny delay in behaviour of auto-approve bot.
        # if the latest application is still in submitted state, let the
        # client know.
        return { 'custom_state': 'submitted' }

    # events are in chronological order, so reverse list to get latest events first
    for event in reversed(application.get('application/events', [])):

        if event.get('event/type') in (REMS_EVENT_REJECTED, REMS_EVENT_CLOSED, REMS_EVENT_REVOKED):

            close_info = {
                'comment': event.get('application/comment'),
                'custom_state': None
            }

            if close_info['comment'] == settings.REMS_SESSION_CLOSE_MESSAGE:
                close_info['custom_state'] = 'session-expired-closed'

            elif close_info['comment'] == settings.REMS_SESSION_CLOSE_MESSAGE_ACTIVE:
                close_info['custom_state'] = 'active-session-expired-closed'

            elif close_info['comment'] == settings.REMS_LOGOUT_MESSAGE:
                close_info['custom_state'] = 'logout-closed'

            elif application['application/state'] == REMS_STATE_CLOSED:
                close_info['custom_state'] = 'manual-closed'

            elif application['application/state'] == REMS_STATE_REJECTED:
                if event.get('event/actor') == settings.REMS_REJECTER_BOT_USER:
                    close_info['custom_state'] = 'automatic-rejected'
                else:
                    close_info['custom_state'] = 'manual-rejected'
            elif application['application/state'] == REMS_STATE_REVOKED:
                close_info['custom_state'] = 'manual-revoked'

            else:
                close_info['custom_state'] = 'unknown-closed'

            return close_info

    logger.error(
        'Closed REMS application did not contain event for closing the application?? Returning 503'
    )

    raise ServiceNotAvailable()


def get_rems_user_application(user_id, application_id):
    """
    Get a specific application of a user from REMS.
    """
    logger.debug('Getting REMS application id %d for user: %s...' % (application_id, user_id))

    headers = {
        'Accept': 'application/json',
        'x-rems-api-key': settings.REMS_API_KEY,
        'x-rems-user-id': user_id,
    }

    try:
        response = http_request('https://%s/api/applications/%d' % (settings.REMS_HOST, application_id), headers=headers)
    except:
        raise ServiceNotAvailable()

    return response.json()


def get_rems_user_applications(user_id, filter_resource=None):
    """
    Get all applications of a user from REMS. Optionally retrieve only applications that
    contain a particular resource. Applications are returned in order of first-submitted date,
    latest application first. NOTE! Excludes unsubmitted applications!
    """
    logger.debug('Getting REMS applications for user: %s...' % user_id)

    headers = {
        'Accept': 'application/json',
        'x-rems-api-key': settings.REMS_API_KEY,
        'x-rems-user-id': user_id,
    }

    try:
        response = http_request('https://%s/api/my-applications' % settings.REMS_HOST, headers=headers)
    except:
        raise ServiceNotAvailable()

    applications = response.json()

    applications = [
        app for app in applications
        if 'application/first-submitted' in app # only applications that have been submitted
        and app['application/state'] != REMS_STATE_DRAFT
    ]

    if filter_resource:

        filtered_applications = []

        for app in applications:
            for resource in app.get('application/resources', []):
                if resource.get('resource/ext-id') == filter_resource:
                    filtered_applications.append(app)

        applications = sorted(
            filtered_applications,
            key=lambda k: k['application/first-submitted'],
            reverse=True
        )

    return applications


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
