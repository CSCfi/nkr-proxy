import os
import pytest


@pytest.fixture
def app():
    """
    App fixture with minimum environment with DEBUG defined
    :return:
    """
    os.environ['DEBUG'] = '1'
    from nkr_proxy.proxy_app import app
    return app


def test_app(app):
    assert app is not None