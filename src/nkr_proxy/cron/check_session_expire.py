# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

from datetime import datetime
import logging
import logging.handlers
import time

import redis

from nkr_proxy.cache import cache
from nkr_proxy.services import rems
from nkr_proxy.settings import settings

"""
Script to be executed in cron to periodically close REMS applications of users who have
been inactive for too long (=no searched in specified timeframe).

Note: For development, execute this script in the following manner:
$ cd nkr-proxy/src
$ CONFIG_PATH=/path/to/config.sh python -m nkr_proxy.cron.check_session_expire
"""

logger = logging.getLogger(__name__)
formatter = logging.Formatter(fmt='%(asctime)s %(process)d %(levelname)s: %(message)s', datefmt='%Y-%m-%dT%H:%M:%S.%03dZ')
formatter.converter = time.gmtime
file_handler = logging.handlers.WatchedFileHandler(settings.CRON_SESSION_EXPIRE_LOG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.setLevel(settings.LOG_LEVEL)


DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
EPOCH = datetime(1970, 1, 1)


class Stats():

    # log total elapsed time of the operation
    start_time = 0
    end_time = 0

    # total recent active users
    n_active_users = 0

    # total applications closed
    n_applications_closed = 0

    # total application close fails
    n_close_failed = 0

    # total application close fails due to active user no longer had an open application
    n_close_missed = 0

    # total unique users who had applications closed
    n_users_close_success = 0

    # total unique users who had applications close fail
    n_users_close_failed = 0

    # log these interesting events to see that these cases can happen
    multiple_applications_closed = False
    multiple_applications_close_failed = False
    only_some_closed = False

    def __init__(self):
        self.start_time = time.time()

    def log_stats(self):
        logger.info('Session check results:')

        if self.n_applications_closed or self.n_close_failed or self.n_close_missed:
            if self.n_applications_closed:
                logger.info(
                    '- %d applications closed for %d users' % (self.n_applications_closed, self.n_users_close_success)
                )
                if self.multiple_applications_closed:
                    logger.info('\t- multiple_applications_closed for some users')
            if self.n_close_failed:
                logger.info('- %d applications failed to close for %d users' % (self.n_close_failed, self.n_users_close_failed))
                if self.multiple_applications_close_failed:
                    logger.info('\t- multiple_applications_close_failed for some users')
            if self.n_close_missed:
                logger.info('- %d users whose applications were already closed or did not exist' % self.n_close_missed)
            if self.only_some_closed:
                logger.info('- only_some_closed for some users')
        else:
            logger.info('- Nothing to do')

        if self.n_active_users:
            logger.info('- %d total active users' % self.n_active_users)

        self.end_time = time.time() - self.start_time

        logger.info('Total time elapsed: %.3f seconds' % self.end_time)

        if self.end_time > settings.SESSION_CLEANUP_MAX_TIME:
            # if the job is taking too long, another cronjob might start executing in parallel.
            # while it should not cause serious problems(?), it will mess up the log.
            logger.warning('SESSION_CLEANUP_MAX_TIME exceeded (%d seconds)' % settings.SESSION_CLEANUP_MAX_TIME)


def user_is_active(last_active_ts, session_max_age_seconds):
    return (round(time.time()) - int(last_active_ts)) < int(session_max_age_seconds)


def close_rems_application(user_id):
    logger.info('Retrieving and closing REMS application for user %s...' % user_id)

    ents = rems.get_rems_entitlements(user_id, full_entitlements=True)

    application_states = []

    logger.debug('User %s entitlements: %s' % (user_id, str(ents)))

    if not ents:
        # no active entitlements. probably application was recently closed by other means
        return None

    for ent in ents:

        logger.debug('Current entitlement in loop: %s' % str(ent))

        if ent['resource'] == settings.METADATA_LEVEL_10_RESOURCE_ID:

            logger.debug('Found resource %s from entitlements' % settings.METADATA_LEVEL_10_RESOURCE_ID)

            application_closed = rems.close_rems_application(
                user_id,
                ent['application-id'],
                settings.REMS_SESSION_CLOSE_MESSAGE,
                close_as_user=settings.REMS_SESSION_CLOSE_USER
            )

            application_states.append({
                'application_id': ent['application-id'],
                'closed': application_closed,
                'user_id': user_id,
            })

            # continue the loop, since in theory the user can have multiple applications
            # open for the same resource.

    if not application_states:
        logger.debug('Did not close any applications')
        return None

    return application_states


def track_registered_only_users():
    """
    Retrieve all approved applications from REMS, and if the applicant is not already
    in activity tracking, add the applicant there, so that the session is closed
    approriately when the session expires.

    It is possible that detected users would make searches later, but in that case
    their last-active timestamp will simply get updated.
    """
    logger.info('Checking for users who have registered but not yet in session tracking...')

    n_registered_only_users = 0

    applications = rems.get_all_rems_applications('approved')

    for app in applications:

        user_id = app['application/applicant']['userid']

        if cache.get(user_id):
            # user is already tracked - do nothing
            continue

        logger.debug('User %s is registered but not tracked' % user_id)

        # app is automatically approved as it is submitted
        date_submitted = app['application/first-submitted']

        epoch_time = (datetime.strptime(date_submitted, DATE_FORMAT) - EPOCH).total_seconds()

        cache.set('user-last-active:%s' % user_id, round(epoch_time))

        n_registered_only_users += 1

    logger.debug('Loaded %d registerd-only users into session tracking' % n_registered_only_users)


def check_and_close_expired_sessions(session_max_age_seconds, max_seconds_after_user_first_active):
    """
    Check all users' cached session activity, and close their REMS application if
    the user is deemed to be inactive.
    After certain time period REMS application is closed regardless of user activity.
    """
    stats = Stats()
    logger.info('//---------------------------------------------------------------')
    logger.info('Begin session checking...')

    track_registered_only_users()

    for key in cache.scan_iter('user-last-active:*'):

        # note: keys are encoded in unicode
        # logger.debug('Current raw key: %s' % str(key))

        user_id = key.decode('utf-8').split('user-last-active:')[1]
        last_active_ts = int(cache.get(key).decode('utf-8'))

        # logger.debug('Current user and ts: %s, %s' % (user_id, last_active_ts))

        if user_is_active(last_active_ts, session_max_age_seconds):
            logger.debug('User %s is active' % user_id)
            stats.n_active_users += 1
            continue
        else:
            logger.info('User %s is inactive' % user_id)

            application_states = close_rems_application(user_id)

            if application_states is None:
                logger.info('User %s had no relevant entitlements to close' % user_id)
                cache.delete(key)
                stats.n_close_missed += 1

            elif all(app['closed'] is True for app in application_states):
                cache.delete(key)
                stats.n_applications_closed += len(application_states)
                stats.n_users_close_success += 1
                if len(application_states) > 1:
                    stats.multiple_applications_closed = True

            elif all(app['closed'] is False for app in application_states):
                stats.n_close_failed += len(application_states)
                stats.n_users_close_failed += 1
                if len(application_states) > 1:
                    stats.multiple_applications_close_failed = True

            else:
                logger.info(
                    'Only some applications were closed for user %s: %s'
                    % (user_id, str(application_states))
                )

                stats.n_applications_closed += len(app for app in application_states if app['closed'] is True)
                stats.n_users_close_success += 1

                stats.n_close_failed += len(app for app in application_states if app['closed'] is False)
                stats.n_users_close_failed += 1

                stats.only_some_closed = True

    for key in cache.scan_iter('user-first-active:*'):   
        
        user_id = key.decode('utf-8').split('user-first-active:')[1]
        user_first_active_ts = round(float(cache.get(key).decode('utf-8')))

        if round(time.time()) - int(max_seconds_after_user_first_active) >= user_first_active_ts:
            
            application_states = close_rems_application(user_id)

            if application_states is None:
                logger.info('Closing session - User %s had no relevant entitlements to close' % user_id)
                cache.delete(key)
                stats.n_close_missed += 1

            elif all(app['closed'] is True for app in application_states):
                cache.delete(key)
                stats.n_applications_closed += len(application_states)
                stats.n_users_close_success += 1
                if len(application_states) > 1:
                    stats.multiple_applications_closed = True

            elif all(app['closed'] is False for app in application_states):
                logger.info('Failed to close application(s)')
                stats.n_close_failed += len(application_states)
                stats.n_users_close_failed += 1
                if len(application_states) > 1:
                    stats.multiple_applications_close_failed = True
            
            else:
                logger.info(
                    'Closing session - some applications were closed for user %s: %s'
                    % (user_id, str(application_states))
                )
                stats.n_applications_closed += len(app for app in application_states if app['closed'] is True)
                stats.n_users_close_success += 1

                stats.n_close_failed += len(app for app in application_states if app['closed'] is False)
                stats.n_users_close_failed += 1

                stats.only_some_closed = True


    stats.log_stats()

    logger.info('---------------------------------------------------------------//')


def main():
    try:
        # check or set special key so that this action is being executed only once in a single process
        if cache.set('session_check_in_progress', 1, nx=True, ex=settings.SESSION_CLEANUP_MAX_TIME):
            # nx=True -> "get or set", only sets this value if did not exist yet
            check_and_close_expired_sessions(settings.SESSION_TIMEOUT_LIMIT, settings.SESSION_TIMEOUT_LONGER_LIMIT)
        else:
            logger.info(
                'Session checking is already being executed by another process '
                '(cache key session_check_in_progress=True). Aborting current process.'
            )
            return
    except redis.exceptions.ConnectionError as e:
        logger.error('Could not connect to Redis: %s' % str(e))
    except Exception as e:
        logger.exception('Checking sessions crashed: %s' % str(e))

    try:
        cache.delete('session_check_in_progress')
    except Exception as e:
        logger.exception('Could not delete redis key session_check_in_progress: %s' % str(e))


if __name__ == '__main__':
    main()
