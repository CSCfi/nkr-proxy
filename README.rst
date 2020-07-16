nkr-proxy
==========

Authorization proxy standing between a REMS instance and a database.

Accepted request methods are GET and POST.


Testing installation
--------------------
Test installation in local VM:

``
curl -k -u nkr-proxy:nkr-proxy 'https://nkr-proxy.csc.local/api/v1/index_search/select?q=*:*&limit=30&rows=30
&fq=+filter(datasource_str_mv:local_ead)'
``

``
curl -k -u nkr-proxy:nkr-proxy -X POST -d 'fl=*&spellcheck=false&facet=true&facet.limit=30&f.building.facet.limit=-1
&facet.field={!ex=building_filter}building&facet.field={!ex=format_ext_str_mv_filter}format_ext_str_mv
&facet.field={!ex=source_available_str_mv_filter}source_available_str_mv
&facet.field={!ex=online_boolean_filter}online_boolean
&facet.field={!ex=peer_reviewed_boolean_filter}peer_reviewed_boolean&f.format_ext_str_mv.facet.limit=-1&facet.sort=count
&f.usage_rights_str_mv.facet.sort=index&f.format.facet.limit=-1&f.sector_str_mv.facet.limit=-1
&f.category_str_mv.facet.limit=-1&facet.mincount=1&sort=score+desc,+first_indexed+desc&hl=false&onCampus=
&fq=-merged_child_boolean:true&wt=json&json.nl=arrarr&rows=20&start=0&q=aineisto'
 'https://nkr-proxy.csc.local/api/v1/index_search/select'
``


License
--------

Copyright (c) 2019 Ministry of Education and Culture, Finland

Licensed under the MIT license, with varying 3rd party libraries licensed under MIT, BSD, and Apache licenses.
