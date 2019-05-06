
import logging
from time import time

from flask import Flask, g, jsonify, make_response, request
import requests

from nkr_proxy.exceptions import *
from nkr_proxy.settings import settings


logger = logging.getLogger(__name__)
app = Flask(__name__)


LEVEL_RESTRICTION_FIELD = settings.LEVEL_RESTRICTION_FIELD


@app.before_request
def before_request():
    g.request_start_time = time()


@app.after_request
def after_request(response):
    duration = '%.3fs' % (time() - g.request_start_time)
    logger.info('%s %s %s %s %s', request.remote_addr, request.method, request.full_path, response.status, duration)
    return response


@app.errorhandler(Exception)
def error_handler_catch_all(e):
    """
    Handler for all "unexpected" exceptions, which translate into
    internal server errors.
    """
    logger.exception('Request ended in an unhandled exception. Returning internal server error 500')
    return make_response(jsonify({'error': 'internal server error'}), 500)


@app.errorhandler(BaseException)
def error_handler_main(error):
    """
    Handler for all "expected" exceptions, which translate into
    various http codes according to exception type.
    """
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@app.route('/api/v1/index_search')
def index_search_root(search_handler=None):
    return make_response('you are probably looking for /api/v1/index_search/<search_handler>', 200)


@app.route('/api/v1/index_search/<path:search_handler>')
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

    user_id = request.headers.get('x-user-id', None)
    query_string = request.query_string.decode('utf-8')

    if user_id is None:
        raise BadRequest('header x-user-id is required')

    if not query_string:
        raise BadRequest('search query is required')

    if settings.DEBUG and request.json and 'debug_entitlements' in request.json:
        entitlements = request.json.pop('debug_entitlements')
        logger.debug('Using debug_entitlements: %r' % entitlements)
    else:
        entitlements = get_rems_entitlements(user_id)

    if not entitlements:
        raise Forbidden('user has no entitlements')

    search_query = generate_permissioned_query('%s?%s' % (search_handler, query_string), entitlements)

    index_results = search_index(entitlements, search_query)

    return make_response(jsonify(index_results), 200)


@app.route("/")
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
    except HttpException:
        raise
    except Exception as e:
        raise ServiceNotAvailable('rems: %r' % e)

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


def generate_permissioned_query(original_query, entitlements):
    """
    Generate a query to augment the original query to index, to only target
    particular permitted documents according to entitlements.
    """
    logger.debug('Adding entitlements to query...')
    for ent in entitlements:
        if ent.endswith('::10'):
            break
    else:
        raise Forbidden('no access to level 10 metadata')

    # level 10 access only
    permission_query = 'fq=+filter(%s:10)' % LEVEL_RESTRICTION_FIELD
    search_query = '%s&%s' % (original_query, permission_query)

    logger.debug('Entitlements added: %s' % permission_query)
    return search_query


def search_index(entitlements, search_query):
    """
    Execute search to index.
    """
    logger.debug('Searching index...')

    full_index_url = '%s/%s/%s' % (settings.INDEX_URL, settings.INDEX_NAME, search_query)

    logger.debug(full_index_url)

    try:
        response = http_request(
            full_index_url,
            auth=(settings.INDEX_USERNAME, settings.INDEX_PASSWORD)
        )
    except HttpException:
        raise
    except Exception as e:
        raise ServiceNotAvailable('index: %r' % e)

    logger.debug('Search successful')
    logger.debug('Validating results against entitlements...')

    resp_json = response.json()

    # ensure response has an expected result object and there are results
    if resp_json.get('response', {}).get('numFound', 0) > 0 \
        and isinstance(resp_json['response'].get('docs', None), list):

        # filter out all results that are not permitted by the entitlements.
        # an additional measure, since the query should already take care of it.
        filtered_results = [
            doc for doc in resp_json['response']['docs']
            # if doc[LEVEL_RESTRICTION_FIELD] == '10' or doc['id'] in entitlements
        ]

        if len(filtered_results) != len(resp_json['response']['docs']):
            # if it so happens that the results differ, we probably want to know about it...
            # messes up paging etc, if included in original response!
            logger.warning('Original query results differ from filtered results!')
            logger.warning('Original results: %d results' % len(resp_json['response']['docs']))
            logger.warning('Verified results: %d results' % len(filtered_results))

        logger.debug('Received %d results from index' % len(filtered_results))

        resp_json['response']['docs'] = filtered_results

    return resp_json


def http_request(*args, method='get', **kwargs):
    if settings.DEBUG:
        kwargs['verify'] = False
        logger.debug('HTTP request begin with data:')
        # logger.debug('args: %r' % args)
        # logger.debug('kwargs: %r' % kwargs)

    try:
        response = getattr(requests, method)(*args, **kwargs)
    except Exception:
        logger.exception('HTTP request failed')
        raise

    logger.debug('HTTP request completed with code: %d' % response.status_code)

    if response.status_code != 200:
        requested_host = response.request.url[:-len(response.request.path_url)]
        message = '%s: %s' % (requested_host, response.content.decode('utf-8'))

        logger.warning(message)

        if response.status_code == 400:
            raise BadRequest(message)
        elif response.status_code == 401:
            raise Unauthorized(message)
        elif response.status_code == 403:
            raise Forbidden(message)
        elif response.status_code == 404:
            raise NotFound(message)
        else:
            raise ServiceNotAvailable(message)

    return response


if __name__ == "__main__":
    app.run(host='127.0.0.1')
