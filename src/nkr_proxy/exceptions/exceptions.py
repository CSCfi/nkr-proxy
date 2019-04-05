
'''
Custom exception classes.
'''

class BaseException(Exception):

    status_code = 500
    message = 'something went wrong'

    def __init__(self, message=None, status_code=None, data=None):

        super().__init__()

        if message is not None:
            self.message = message

        if status_code is not None:
            self.status_code = status_code

        self.data = data

    def to_dict(self):

        val = { 'message': self.message }

        if self.data is not None:
            val['details'] = self.data

        if self.status_code is not None:
            val['status_code'] = self.status_code

        return val


class HttpException(BaseException):
    pass


class BadRequest(HttpException):
    '''
    Invalid parameters or otherwise something wrong with request data.
    '''
    status_code = 400
    message = 'bad request'


class Unauthorized(HttpException):
    '''
    Missing or invalid authentication.
    '''
    status_code = 401
    message = 'unauthorized'


class Forbidden(HttpException):
    '''
    Authentication ok, but access denied to requested resource or action.
    '''
    status_code = 403
    message = 'forbidden'


class NotFound(HttpException):
    '''
    Requested resource not found.
    '''
    status_code = 404
    message = 'not found'


class ServiceNotAvailable(HttpException):
    '''
    Unable to complete request due to some remote service being unable to respond properly.
    '''
    status_code = 503
    message = 'service not available'
