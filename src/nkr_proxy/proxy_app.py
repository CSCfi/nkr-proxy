# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

import logging
from base64 import b64encode
from random import shuffle
from time import time

from flask import Flask, g, Blueprint, jsonify, make_response, request
import requests
import werkzeug

from nkr_proxy.exceptions import *
from nkr_proxy.settings import settings
from nkr_proxy.cache import cache
from nkr_proxy.utils import http_request
from nkr_proxy.services import rems


logger = logging.getLogger(__name__)

LEVEL_10_RESOURCE_ID = settings.METADATA_LEVEL_10_RESOURCE_ID
LEVEL_RESTRICTION_FIELD = settings.LEVEL_RESTRICTION_FIELD
DOCUMENT_UNIQUE_ID_FIELD = settings.DOCUMENT_UNIQUE_ID_FIELD
ADDITIONAL_INDEX_QUERY_FIELDS = [DOCUMENT_UNIQUE_ID_FIELD, LEVEL_RESTRICTION_FIELD]
VERIFY_TLS = settings.VERIFY_TLS


bp = Blueprint('api', __name__)


@bp.app_errorhandler(Exception)
def error_handler_catch_all(e):
    """
    Handler for all "unexpected" exceptions, which translate into
    internal server errors.
    """
    if isinstance(e, werkzeug.exceptions.MethodNotAllowed):
        return make_response(jsonify({ 'message': str(e) }), 405)

    logger.exception('Request ended in an unhandled exception. Returning internal server error 500')

    return make_response(jsonify({'error': 'internal server error'}), 500)


@bp.app_errorhandler(BaseException)
def error_handler_main(error):
    """
    Handler for all "expected" exceptions, which translate into
    various http codes according to exception type.
    """
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@bp.route('/api/v1/index_search', methods=['GET'])
def index_search_root(search_handler=None):
    raise BadRequest('you are probably looking for /api/v1/index_search/<search_handler>')


@bp.route('/api/v1/index_search/<path:search_handler>', methods=['GET','POST'])
def index_search(search_handler=None):
    """
    Entrypoint for searching index withing the limits for entitlements
    from entitlement management system.

    - Get user entitlements
    - Augment search query according to entitlements
    - Execute query to index
    - Return results
    """
    logger.debug('Begin index_search')

    response_headers = {}

    if search_handler not in settings.INDEX_ALLOWED_APIS:
        raise BadRequest('Invalid search handler. Valid search handlers are: %s' % settings.INDEX_ALLOWED_APIS)

    user_id = request.headers.get('x-user-id', None)

    query_string = ""
    method = ""

    if request.method == 'GET':
        query_string = request.query_string.decode('utf-8')
        method = request.method.lower()
        logger.debug('Get request query string %s', query_string)
    
    if request.method == 'POST':
        raw_data = request.get_data()
        logger.debug('Raw data: %s' % raw_data)
        query_string = raw_data.decode('utf-8')
        method = request.method.lower()
        
    if not query_string:
        logger.debug('Could not find query_string')
        raise BadRequest('search query is required')

    if settings.DEBUG and request.json and 'debug_entitlements' in request.json:
        entitlements = request.json.pop('debug_entitlements')
        logger.debug('Using debug_entitlements: %r' % entitlements)
    elif user_id is None:
        logger.debug('No header x-user-id provided. Using entitlements = []')
        entitlements = []
    else:
        logger.debug('Header x-user-id == %s' % user_id)

        entitlements = rems.get_rems_entitlements(user_id)

        if LEVEL_10_RESOURCE_ID in entitlements:
            # user has an active level 10 entitlemnt -> track user activity
            cache.set('user-last-active:%s' % user_id, round(time()))
            response_headers['x-user-access-status'] = 'ok'
        else:
            # check if user has a last-known-application, check its status,
            # and make that info available in the response
            apps = rems.get_rems_user_applications(
                user_id,
                filter_resource=LEVEL_10_RESOURCE_ID
            )

            if apps:
                # another GET to a particular application, to get its event data
                app = rems.get_rems_user_application(user_id, apps[0]['application/id'])

                # form a response based on application event data
                close_info = rems.get_rems_application_close_info(app)

                response_headers['x-user-access-status'] = close_info['custom_state']

                if 'comment' in close_info:
                    response_headers['x-user-access-status-comment'] = \
                        b64encode(close_info['comment'].encode('utf-8')).decode('utf-8')
            else:
                # user did not have entitlements, but also never any submitted applications
                response_headers['x-user-access-status'] = 'no-applications'

            # additionally, check if user is currently blacklisted. this information
            # complements states "automatic-rejected" and "manual-revoked", which imply
            # the user was recently blacklisted in an application, but since then may
            # also have been returned access
            blacklisted = rems.check_user_blacklisted(user_id, LEVEL_10_RESOURCE_ID)
            if blacklisted.get('blacklisted'):
                response_headers['x-user-blacklisted'] = blacklisted.get('date', '-')

    search_query, user_restriction_level = generate_query_restrictions(
        user_id, '%s?%s' % (search_handler, query_string), entitlements
    )

    logger.debug('Search query: %s', search_query)
    logger.debug('User restriction level: %s', user_restriction_level)

    index_results = search_index(user_restriction_level, entitlements, search_query, method)

    response = make_response(jsonify(index_results), 200)

    for h, v in response_headers.items():
        response.headers[h] = v

    return response


@bp.route("/")
def hello():
    logging.info('hello')
    return "<h1 style='color:blue'>Hello There!</h1>"


def generate_query_restrictions(user_id, original_query, entitlements):
    """
    Generate a query to augment the original query to index, to only target
    particular permitted documents according to entitlements. Additionally,
    return the general restriction level of the user which is used for
    verification filtering after the query.
    """
    logger.debug('Adding entitlements to query...')

    user_restriction_level = '00'

    for ent in entitlements:
        if ent == LEVEL_10_RESOURCE_ID:
            # level 10 access only
            logger.debug('Found level 10 entitlement: %s' % ent)
            logger.info('User %s has level 10 access' % user_id)
            permission_query = 'fq=+filter(%s:10)' % LEVEL_RESTRICTION_FIELD
            user_restriction_level = '10'
            break
    else:
        # open metadata access only
        logger.debug('No level 10 entitlements found. Adding filter for level 0')
        logger.info('User %s has no entitlements' % user_id)
        permission_query = 'fq=+filter(%s:00)' % LEVEL_RESTRICTION_FIELD

    search_query = '%s&%s' % (original_query, permission_query)

    if 'fl=' in original_query:
        # if query parameter fl is not defined, all fields are retrieved by default.
        # if specific fields are defined, ensure that fields needed for validation
        # are present in the query.
        search_query += '&fl=%s' % '%2C'.join(ADDITIONAL_INDEX_QUERY_FIELDS)

    logger.debug('Entitlements added: %s' % permission_query)
    logger.debug('Adding user_restriction_level: %r' % user_restriction_level)
    return search_query, user_restriction_level


def search_index(user_restriction_level, entitlements, search_query, method):
    """
    Execute search to index.
    """
    logger.debug('Searching index...')

    shuffle(settings.INDEX_HOSTS)

    for n_retry, index_host in enumerate(settings.INDEX_HOSTS):

        #full_index_url = '%s/%s/%s' % (index_host, settings.INDEX_NAME, search_query)

        #logger.debug(full_index_url)

        try:
            if method == 'get':
                logger.debug('Method: %s', method)
                full_index_url = '%s/%s/%s' % (index_host, settings.INDEX_NAME, search_query)
                response = http_request(
                    method,
                    full_index_url,
                    auth=(settings.INDEX_USERNAME, settings.INDEX_PASSWORD)
                )
                logger.debug(full_index_url)
            if method == 'post':
                logger.debug('Method: %s', method)
                full_index_url = '%s/%s/select' % (index_host, settings.INDEX_NAME)
                response = http_request(
                    method,
                    full_index_url,
                    search_query,
                    auth=(settings.INDEX_USERNAME, settings.INDEX_PASSWORD)
                )
                logger.debug(full_index_url)     
        except (Unauthorized, Forbidden) as e:
            logger.error(e.message)
            raise ServiceNotAvailable()
        except BadRequest as e:
            if settings.DEBUG:
                raise
            raise BadRequest('index returned: 400, bad request')
        except requests.exceptions.ConnectionError:
            n_retry += 1 # offset since enumeration began from 0
            if n_retry >= len(settings.INDEX_HOSTS):
                raise ServiceNotAvailable()
            logging.info('Connection to index failed, trying another host... (retry attempt #%d)' % n_retry)
        else:
            break

    logger.debug('Search successful')
    logger.debug('Validating results against entitlements...')

    resp_json = response.json()
    unexpected_data = False

    if 'response' not in resp_json:
        logger.error('index response does not contain key: "response"')
        unexpected_data = True
    elif 'numFound' not in resp_json['response']:
        logger.error('index response does not contain key: "numFound"')
        unexpected_data = True
    elif 'docs' not in resp_json['response']:
        logger.error('index response does not contain key: "docs"')
        unexpected_data = True
    elif not isinstance(resp_json['response']['docs'], list):
        logger.error('index response "docs" key is not a list')
        unexpected_data = True

    if unexpected_data:
        # prevent possible leak of results other than document search results
        raise BadRequest('index returned data in unexpected format')

    # filter out all results that are not permitted by the entitlements.
    # an additional measure, since the query should already take care of it.
    try:
        filtered_results = [
            doc for doc in resp_json['response']['docs']
            if doc[LEVEL_RESTRICTION_FIELD] == str(user_restriction_level)
            or doc[DOCUMENT_UNIQUE_ID_FIELD] in entitlements
        ]
    except KeyError:
        logger.exception('Index response results does not contain a required key')
        raise BadRequest('index returned data in unexpected format')

    if len(filtered_results) != len(resp_json['response']['docs']):
        # if it so happens that the results differ, we probably want to know about it...
        # messes up paging etc, if included in original response!
        logger.warning('Original query results differ from filtered results!')
        logger.warning('Original results: %d results' % len(resp_json['response']['docs']))
        logger.warning('Verified results: %d results' % len(filtered_results))

    logger.debug('Received %d verified results from index' % len(filtered_results))

    resp_json['response']['docs'] = filtered_results

    return resp_json


def before_request():
    g.request_start_time = time()
    logger.info(
        '%s [%s] - %s %s',
        request.remote_addr,
        request.headers.get('x-user-id', '-'),
        request.method,
        request.full_path
    )


def after_request(response):
    duration = '%.3fs' % (time() - g.request_start_time)
    logger.info(
        '%s [%s] - %s %s %s %s',
        request.remote_addr,
        request.headers.get('x-user-id', '-'),
        request.method,
        request.full_path,
        response.status,
        duration
    )
    return response


bp.after_request(after_request)
bp.before_request(before_request)

app = Flask(__name__)
app.register_blueprint(bp)


if __name__ == "__main__":
    app.run(host='127.0.0.1')
