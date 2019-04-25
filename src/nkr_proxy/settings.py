import os


class Settings():

    NKR_PROXY_CONF_VARS = (
        'DEBUG',
        'INDEX_URL',
        'INDEX_NAME',
        'INDEX_USERNAME',
        'INDEX_PASSWORD',
        'LEVEL_RESTRICTION_FIELD',
        'LOG_LEVEL',
        'REMS_API_KEY',
        'REMS_URL',
    )

    def __init__(self):
        for env_var in self.NKR_PROXY_CONF_VARS:
            setattr(self, env_var, os.environ.get(env_var, None))

    def __repr__(self):
        vars_list = []
        for var in self.NKR_PROXY_CONF_VARS:
            vars_list.append('%s=%r' % (var, getattr(self, var, None)))
        return '\n'.join(vars_list)
        

settings = Settings()
