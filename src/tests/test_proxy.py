# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

import logging
import os

import pytest
import responses

from nkr_proxy.settings import settings


"""
nkr-proxy tests

Before running this test suite, a real Solr core is created and loaded with
pre-defined test data. REMS-api is mocked to return a pre-defined list of
entitlements, but in most tests requests to Solr are sent to a real Solr instance.
Some test cases do mock Solr in order to test failures or weird responses.

Most configuration parameters from config.sh are used during tests, but some
parameters are overrided in test_config.sh.

The tests can only be run in local development environment.

See more info in nkr-proxy/src/run-tests script about how test env is set up.

Some notes about the test cases:

- In some tests, "caplog.set_level(logging.<log_level>)" is used to suppress logs
when a warning or error is expected to be logger. This is simply to keep the console
log tidy and easier to read. If a test fails, uncomment these lines to help debugging.
"""


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

FULL_INDEX_URL = '%s/%s/select' % (settings.INDEX_HOSTS[0], settings.INDEX_NAME)

REMS_BLACKLIST_API = 'https://%s/api/blacklist' % settings.REMS_HOST
REMS_ENTITLEMENTS_API = 'https://%s/api/entitlements' % settings.REMS_HOST
REMS_MY_APPLICATIONS_API = 'https://%s/api/my-applications' % settings.REMS_HOST


def _mock_rems_blacklist_ok():
    """
    Helper method: REMS /api/blacklist returns empty list, meaning current test user
    is not blacklisted for any resource.
    """
    responses.add(
        'GET',
        REMS_BLACKLIST_API,
        status=200,
        content_type='application/json',
        json=[]
    )


class BaseTestClass():

    @classmethod
    def setup_class(cls):
        cls._headers = {
            'x-user-id': 'userid'
        }

    @pytest.fixture
    def app(self):
        """
        App fixture with minimum environment with DEBUG defined
        :return:
        """
        if settings.NKR_ENV != 'local_development':
            raise Exception('test should only be executed in local development environment.')

        os.environ['DEBUG'] = '1'
        os.environ['TEST'] = '1'

        from nkr_proxy.proxy_app import app, bp
        app.register_blueprint(bp)

        return app

    @pytest.fixture
    def client(self, app):
        return app.test_client()

    def _assert_response_metadata_level(self, response, level):
        assert 'response' in response.json, 'not solr response?'
        assert 'docs' in response.json['response'], 'not solr response?'
        assert len(response.json['response']['docs']) > 0, 'response should contain results'

        for doc in response.json['response']['docs']:
            assert doc[settings.LEVEL_RESTRICTION_FIELD] == str(level), 'should return level %d metadata only' % level


class TestAPIBasics(BaseTestClass):


    # basic api accessibility tests


    def test_index_search_api_missing_search_handler(self, client):
        response = client.get('/api/v1/index_search')
        assert response.status_code == 400
        assert 'looking for' in response.json['message']

    def test_index_search_api_responds(self, client):
        response = client.get('/api/v1/index_search/select?q=test')
        assert response.status_code == 200, response.data

    def test_index_search_api_invalid_http_verb(self, client):
        """
        Ensure only whitelisted HTTP verbs are let through.
        """
        for verb in ['delete', 'put', 'patch']:
            response = getattr(client, verb)('/api/v1/index_search/select?q=test')
            assert response.status_code == 405, 'verb %s should not work' % verb


class TestREMSBasics(BaseTestClass):


    # rems basic accessiblity


    def test_rems_not_reachable(self, client, caplog):
        """
        Should fail gracefully and return 503.
        """
        caplog.set_level(logging.CRITICAL) # error is expected
        response = client.get('/api/v1/index_search/select?q=test', headers=self._headers)
        assert response.status_code == 503, response.data

    @responses.activate
    def test_rems_wrong_apikey(self, client, caplog):
        """
        Should fail gracefully and return 503.
        """
        responses.add(
            'GET',
            REMS_ENTITLEMENTS_API,
            status=401,
            content_type='application/json',
            body='invalid api key'
        )

        caplog.set_level(logging.CRITICAL) # error is expected

        response = client.get('/api/v1/index_search/select?q=test', headers=self._headers)
        assert response.status_code == 503, response.data

        assert responses.calls[0].request.url == REMS_ENTITLEMENTS_API
        assert responses.calls[0].response.status_code == 401


class TestREMSEntitlements(BaseTestClass):


    # entitlements checking tests


    @classmethod
    def setup_method(cls):
        responses.add_passthru(settings.INDEX_HOSTS[0])

    def test_rems_user_not_provided(self, client):
        """
        Header x-user-id missing should give default access to
        public metadata.
        """
        response = client.get('/api/v1/index_search/select?q=*:*', headers={})
        assert response.status_code == 200, response.data
        self._assert_response_metadata_level(response, '00')

    @responses.activate
    def test_rems_user_not_found(self, client):
        """
        This test is actually idential to "test_entitlements_list_empty".

        Given user not found in REMS should return public metadata: REMS will
        return an empty list of entitlements.
        """
        _mock_rems_blacklist_ok()

        responses.add(
            'GET',
            REMS_ENTITLEMENTS_API,
            status=200,
            content_type='application/json',
            json=[]
        )

        responses.add(
            'GET',
            REMS_MY_APPLICATIONS_API,
            status=200,
            content_type='application/json',
            json=[]
        )

        response = client.get('/api/v1/index_search/select?q=*:*', headers=self._headers)
        assert response.status_code == 200, response.data
        assert responses.calls[0].request.url == REMS_ENTITLEMENTS_API

        self._assert_response_metadata_level(response, '00')


    @responses.activate
    def test_entitlements_list_empty(self, client):
        """
        Should return public metadata, and response headers contains information that
        user does not have any applications.
        """
        _mock_rems_blacklist_ok()

        responses.add(
            'GET',
            REMS_ENTITLEMENTS_API,
            status=200,
            content_type='application/json',
            json=[]
        )

        responses.add(
            'GET',
            REMS_MY_APPLICATIONS_API,
            status=200,
            content_type='application/json',
            json=[]
        )

        response = client.get('/api/v1/index_search/select?q=*:*', headers=self._headers)
        assert response.status_code == 200, response.data
        assert response.headers['x-user-access-status'] == 'no-applications'
        assert responses.calls[0].request.url == REMS_ENTITLEMENTS_API
        assert responses.calls[1].request.url == REMS_MY_APPLICATIONS_API

        self._assert_response_metadata_level(response, '00')


    @responses.activate
    def test_entitlements_only_level_10(self, client):
        """
        Should give access to all level 10 metadata.
        """
        responses.add(
            'GET',
            REMS_ENTITLEMENTS_API,
            status=200,
            content_type='application/json',
            json=[
                {
                    "resource": settings.METADATA_LEVEL_10_RESOURCE_ID,
                    "application-id": 1,
                    "start": "2019-05-21T11:51:23.254Z",
                    "end": None,
                    "mail": self._headers['x-user-id']
                },
            ]
        )

        response = client.get('/api/v1/index_search/select?q=*:*', headers=self._headers)
        assert response.status_code == 200, response.data
        assert responses.calls[0].request.url == REMS_ENTITLEMENTS_API

        self._assert_response_metadata_level(response, '10')


class TestSolrBasics(BaseTestClass):


    # solr basic accessiblity


    def test_solr_not_reachable(self, client, caplog, monkeypatch):
        """
        Should fail gracefully and return 503.
        """
        # let there be a real connection error
        monkeypatch.setattr(settings, 'INDEX_HOSTS', ['https://mock-index-url.nope'])
        responses.add_passthru('https://mock-index-url.nope')

        caplog.set_level(logging.CRITICAL) # error is expected
        response = client.get('/api/v1/index_search/select?q=*:*', headers={})
        assert response.status_code == 503, response.data

    @responses.activate
    def test_solr_wrong_auth_credentials(self, client, caplog):
        """
        Should fail gracefully and return 503.
        """
        responses.add(
            'GET',
            FULL_INDEX_URL,
            status=401,
            content_type='application/json',
            body='invalid auth'
        )

        caplog.set_level(logging.CRITICAL) # error is expected
        response = client.get('/api/v1/index_search/select?q=*:*', headers={})
        assert response.status_code == 503, response.data

    def test_invalid_solr_api_post_request(self, client):
        """
        Ensure only whitelisted Solr APIs are let through.
        """
        response = client.post('/api/v1/index_search/invalid?q=test')
        assert response.status_code == 400

        response = client.post('/api/v1/index_search/select?','fl=*&spellcheck=false&facet=true&facet.limit=30&f.building.facet.limit=-1&facet.field={!ex=building_filter}building&facet.field={!ex=format_ext_str_mv_filter}format_ext_str_mv&facet.field={!ex=source_available_str_mv_filter}source_available_str_mv&facet.field={!ex=online_boolean_filter}online_boolean&facet.field={!ex=peer_reviewed_boolean_filter}peer_reviewed_boolean&f.format_ext_str_mv.facet.limit=-1&facet.sort=count&f.usage_rights_str_mv.facet.sort=index&f.format.facet.limit=-1&f.sector_str_mv.facet.limit=-1&f.category_str_mv.facet.limit=-1&facet.mincount=1&sort=score+desc,+first_indexed+desc&hl=false&onCampus=&fq=-merged_child_boolean:true&wt=json&json.nl=arrarr&rows=20&start=0&q=mattila')
        assert response.status_code == 200, 'tried select api. response: %s' % (response.data)


class TestSolrResponseValidation(BaseTestClass):


    # solr response validation tests


    @responses.activate
    def test_solr_response_invalid_structure(self, client, caplog):
        """
        Fail if solr response has unexpected structure.
        """
        responses.add(
            'GET',
            FULL_INDEX_URL,
            status=200,
            content_type='application/json',
            json={
                'response': {
                    'data': {
                        'something': 'unexpected'
                    }
                }
            }
        )

        caplog.set_level(logging.CRITICAL) # error is expected
        response = client.get('/api/v1/index_search/select?q=*:*', headers={})
        assert response.status_code == 400, response.data

    @responses.activate
    def test_solr_response_missing_level_restriction_field(self, client, caplog):
        """
        Fail if document misses field which defines its sensitivity level.
        """
        responses.add(
            'GET',
            FULL_INDEX_URL,
            status=200,
            content_type='application/json',
            json={
                'response': {
                    'numFound': 1,
                    'docs': [
                        { 'id': 'abc-123', 'description': 'stuff' }
                    ]
                }
            }
        )

        caplog.set_level(logging.CRITICAL) # error is expected
        response = client.get('/api/v1/index_search/select?q=*:*', headers={})
        assert response.status_code == 400, response.data

    @responses.activate
    def test_solr_response_document_level_does_not_match_user_restriction_level(self, client, caplog):
        """
        If the query is made in a way that manages to search and return documents that
        do not match the user's entitlements, the proxy should filter out such results.

        In addition the proxy should log plenty of warnings in that case, but that part
        is not tested here.
        """
        _mock_rems_blacklist_ok()

        responses.add(
            'GET',
            REMS_ENTITLEMENTS_API,
            status=200,
            content_type='application/json',
            json=[{
                "resource": "urn:nbn:fi:something-else-entirely-but-not-level-10",
                "application-id": 2,
                "start": "2019-05-21T11:51:23.254Z",
                "end": None,
                "mail": "RDapplicant1@csc.fi"
            }]
        )

        responses.add(
            'GET',
            REMS_MY_APPLICATIONS_API,
            status=200,
            content_type='application/json',
            json=[]
        )

        responses.add(
            'GET',
            FULL_INDEX_URL,
            status=200,
            content_type='application/json',
            json={
                'response': {
                    'numFound': 1,
                    'docs': [{
                        'id': 'abc-123',
                        '_document_id': 'abc-123-def',
                        'description': 'stuff',
                        settings.LEVEL_RESTRICTION_FIELD: settings.METADATA_LEVEL_10_RESOURCE_ID
                    }]
                }
            }
        )

        caplog.set_level(logging.ERROR) # warning is expected
        response = client.get('/api/v1/index_search/select?q=*:*', headers=self._headers)
        assert response.status_code == 200, response.data
        assert len(response.json['response']['docs']) == 0


class TestSolrAbuse(BaseTestClass):


    # solr "misuse" query tests

    # ensure handcrafted odd queries do not return data of higher levels than permitted.


    def test_invalid_solr_api(self, client):
        """
        Ensure only whitelisted Solr APIs are let through.
        """
        response = client.get('/api/v1/index_search/invalid?q=test')
        assert response.status_code == 400

        for api in settings.INDEX_ALLOWED_APIS:
            response = client.get('/api/v1/index_search/%s?q=test' % api)
            assert response.status_code == 200, 'tried api: %s. response: %s' % (api, response.data)

    def test_query_added_fq_filter_10(self, client):
        """
        Ensure query does not return results if original query already has included
        entitlements like fq=+filter(LEVEL_RESTRICTION_FIELD:10).

        The query should return successfully, but since there will be two "AND" clauses
        that can never be true simultaneously, there must be 0 total results.
        """
        response = client.get(
            '/api/v1/index_search/select?q=*:*&fq=+filter(%s:10)' % settings.LEVEL_RESTRICTION_FIELD,
            headers={}
        )
        assert response.status_code == 200, response.data
        assert len(response.json['response']['docs']) == 0
