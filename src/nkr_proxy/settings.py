import os


NKR_PROXY_CONF_VARS = (
    'DEBUG',
    'INDEX_URL',
    'INDEX_NAME',
    'INDEX_USERNAME',
    'INDEX_PASSWORD',
    'LOG_LEVEL',
    'REMS_API_KEY',
    'REMS_URL',
)


class Settings():

    def __repr__(self):
        vars_list = []
        for var in NKR_PROXY_CONF_VARS:
            vars_list.append('%s=%r' % (var, getattr(self, var, None)))
        return '\n'.join(vars_list)
        

settings = Settings()


for env_var in NKR_PROXY_CONF_VARS:
    setattr(settings, env_var, os.environ.get(env_var, None))
