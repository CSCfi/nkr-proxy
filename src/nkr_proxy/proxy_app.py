# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

import logging
from random import shuffle
from time import time

from flask import Flask, g, Blueprint, jsonify, make_response, request
import requests
import werkzeug

from nkr_proxy.exceptions import *
from nkr_proxy.settings import settings


logger = logging.getLogger(__name__)

LEVEL_10_RESOURCE_ID = settings.METADATA_LEVEL_10_RESOURCE_ID
LEVEL_RESTRICTION_FIELD = settings.LEVEL_RESTRICTION_FIELD
DOCUMENT_UNIQUE_ID_FIELD = settings.DOCUMENT_UNIQUE_ID_FIELD
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


@bp.route('/api/v1/index_search/<path:search_handler>', methods=['GET'])
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

    if search_handler not in settings.INDEX_ALLOWED_APIS:
        raise BadRequest('Invalid search handler. Valid search handlers are: %s' % settings.INDEX_ALLOWED_APIS)

    user_id = request.headers.get('x-user-id', None)
    query_string = request.query_string.decode('utf-8')

    if not query_string:
        raise BadRequest('search query is required')

    if settings.DEBUG and request.json and 'debug_entitlements' in request.json:
        entitlements = request.json.pop('debug_entitlements')
        logger.debug('Using debug_entitlements: %r' % entitlements)
    elif user_id is None:
        logger.debug('No header x-user-id provided. Using entitlements = []')
        entitlements = []
    else:
        logger.debug('Header x-user-id == %s' % user_id)
        entitlements = get_rems_entitlements(user_id)

    search_query, user_restriction_level = generate_query_restrictions(
        '%s?%s' % (search_handler, query_string), entitlements
    )

    index_results = search_index(user_restriction_level, entitlements, search_query)

    return make_response(jsonify(index_results), 200)


@bp.route("/")
def hello():
    logging.info('hello')
    return "<h1 style='color:blue'>Hello There!</h1>"


def get_rems_entitlements(user_id):

    logger.debug('Retrieving entitlements for user: %s...' % user_id)

    headers = {
        'Accept': 'application/json',
        'x-rems-api-key': settings.REMS_API_KEY,
        'x-rems-user-id': user_id,
    }

    try:
        response = http_request(settings.REMS_URL, headers=headers)
    except:
        raise ServiceNotAvailable()

    if response.status_code == 401:
        raise Unauthorized('rems: %s' % response.content.decode('utf-8'))
    elif response.status_code == 403:
        raise Forbidden('rems: %s' % response.content.decode('utf-8'))

    entitlements = response.json()

    if settings.DEBUG:
        logger.debug('Received %d entitlements for user %s' % (len(entitlements), user_id))
        logger.debug('Entitlements:')
        for ent in entitlements:
            logger.debug('- %s' % ent['resource'])

    # only care about the resource identifiers from the response
    return [ ent['resource'] for ent in entitlements ]


def generate_query_restrictions(original_query, entitlements):
    """
    Generate a query to augment the original query to index, to only target
    particular permitted documents according to entitlements. Additionally,
    return the general restriction level of the user which is used for
    verification filtering after the query.
    """
    logger.debug('Adding entitlements to query...')

    user_restriction_level = 0

    for ent in entitlements:
        if ent == LEVEL_10_RESOURCE_ID:
            # level 10 access only
            logger.debug('Found level 10 entitlement: %s' % ent)
            permission_query = 'fq=+filter(%s:10)' % LEVEL_RESTRICTION_FIELD
            user_restriction_level = 10
            break
    else:
        # open metadata access only
        logger.debug('No level 10 entitlements found. Adding filter for level 0')
        permission_query = 'fq=+filter(%s:0)' % LEVEL_RESTRICTION_FIELD

    search_query = '%s&%s' % (original_query, permission_query)

    logger.debug('Entitlements added: %s' % permission_query)
    logger.debug('Adding user_restriction_level: %d' % user_restriction_level)
    return search_query, user_restriction_level


def search_index(user_restriction_level, entitlements, search_query):
    """
    Execute search to index.
    """
    logger.debug('Searching index...')

    shuffle(settings.INDEX_HOSTS)

    for n_retry, index_host in enumerate(settings.INDEX_HOSTS):

        full_index_url = '%s/%s/%s' % (index_host, settings.INDEX_NAME, search_query)

        logger.debug(full_index_url)

        try:
            response = http_request(
                full_index_url,
                auth=(settings.INDEX_USERNAME, settings.INDEX_PASSWORD),
                headers=settings.INDEX_HEADERS
            )
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


def http_request(*args, method='get', **kwargs):
    if settings.DEBUG:
        logger.debug('HTTP request begin with data:')
        # logger.debug('args: %r' % args)
        # logger.debug('kwargs: %r' % kwargs)

    try:
        response = getattr(requests, method)(*args, verify=VERIFY_TLS, **kwargs)
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


def before_request():
    g.request_start_time = time()


def after_request(response):
    duration = '%.3fs' % (time() - g.request_start_time)
    logger.info('%s %s %s %s %s', request.remote_addr, request.method, request.full_path, response.status, duration)
    return response


bp.after_request(after_request)
bp.before_request(before_request)

app = Flask(__name__)
app.register_blueprint(bp)


if __name__ == "__main__":
    app.run(host='127.0.0.1')
