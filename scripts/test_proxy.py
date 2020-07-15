import requests
import pprint

#env = 'local'
env = 'test'

headers = {
    'x-user-id': '<test-env-proxy-user-id>',
    # 'x-user-id': 'test:b101',
    # 'x-user-id': 'nope',

}
if env == 'local':
    auth = ('nkr-proxy', 'nkr-proxy')
    proxy_host = 'nkr-proxy.csc.local'

elif env == 'test':
    auth = ('<test-env-proxy-user>', '<test-env-proxy-passwd>')
    proxy_host = '<test-env-proxy-host>'


response = requests.get(
    'https://%s/api/v1/index_search/select?q=*:*&limit=30&rows=30&fq=+filter(datasource_str_mv:local_ead)' % proxy_host,
    # 'https://%s/api/v1/index_search/select?fl=*,score&wt=json&json.nl=arrarr&q=id:"123-ABC"' % proxy_host,
    # 'https://%s/api/v1/index_search/select?fl=*,score&wt=json&json.nl=arrarr&q=id:"456-DEF"' % proxy_host,
    # 'https://%s/api/v1/index_search/select?fl=*,score&wt=json&json.nl=arrarr&q=*:*&rows:1' % proxy_host,
    # 'https://%s/api/v1/index_search/select?q=*:*&rows:5' % proxy_host,
    # json={
    #     'query': "*:*",
    #     'limit': 10,
    #     'fields': "id title author",
    #     'filter': "title:document",

    #     # comment below line to actually retrieve entitlements from
    #     # rems for user defined in headers
    #     # 'debug_entitlements': ['some-entitlement::10', 'more::20']
    #     # 'debug_entitlements': ['some-entitlement::30', 'more::20']
    # },
    auth=auth,
    headers=headers,
    verify=False
)

print(response.status_code)
print(response.headers)
try:
    pprint.pprint(response.json())
except:
    pprint.pprint(response.content)
