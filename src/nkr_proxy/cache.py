# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

from redis.client import Redis

from nkr_proxy.settings import settings


cache = Redis(
    host=settings.CACHE_HOST,
    port=int(settings.CACHE_PORT),
    password=settings.CACHE_PASSWORD,
    socket_timeout=float(settings.CACHE_SOCKET_TIMEOUT),
    db=int(settings.CACHE_DB)
)
