from ctypes import cdll, c_char_p, Structure
import os
import sys

class Auth(Structure):
    _fields_ = [
        ('cookies', c_char_p),
        ('ctx', c_char_p),
        ('errStr', c_char_p),
    ]

current_dir = os.path.dirname(os.path.abspath(__file__))
lib = cdll.LoadLibrary(current_dir + '/ms_auth.dll') if sys.platform == 'win32' else cdll.LoadLibrary(current_dir + '/ms_auth.so')

_auth = lib.auth
_auth.argtypes = [c_char_p, c_char_p, c_char_p]
_auth.restype = Auth

_authEmail = lib.authEmail
_authEmail.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]
_authEmail.restype = Auth

_authDevice = lib.authDevice
_authDevice.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
_authDevice.restype = Auth

class msAuth:
    def __init__(self, account, authType, password='') ->None:
        self.account = account.encode('utf-8')
        self.password = password.encode('utf-8')
        self.authType = authType.encode('utf-8')

    def auth(self) -> tuple[str, str]:
        try:
            res = _auth(self.account, self.password, self.authType)
            err = res.errStr.decode('utf-8')
            if err != '' and err != 'email login need code to continue' and not err.startswith('device login need handler to continue'):
                raise Exception(res.errStr.decode('utf-8'))
            self.ctx = res.ctx
            self.cookies = res.cookies
            if err.startswith('device login need handler to continue'):
                self.code = err.split(' ')[-1]
            return res.cookies.decode('utf-8'), res.errStr.decode('utf-8')
        except KeyboardInterrupt:
            pass

    def authEmail(self, code) -> tuple[str, str]:
        try:
            res = _authEmail(self.account, code.encode('utf-8'), self.authType, self.ctx, self.cookies)
            if res.errStr.decode('utf-8') != '':
                raise Exception(res.errStr.decode('utf-8'))
            self.cookies = res.cookies
            return res.cookies.decode('utf-8'), res.errStr.decode('utf-8')
        except KeyboardInterrupt:
            pass

    def authDevice(self) -> tuple[str, str]:
        try:
            res = _authDevice(self.account, self.authType, self.ctx, self.cookies)
            if res.errStr.decode('utf-8') != '':
                raise Exception(res.errStr.decode('utf-8'))
            self.cookies = res.cookies
            return res.cookies.decode('utf-8'), res.errStr.decode('utf-8')
        except KeyboardInterrupt:
            pass
    
    def getCode(self) -> str:
        return self.code
    
    def getCookie(self) -> str:
        return self.cookies

if __name__ == '__main__':

    print('Test passwd')
    auth = msAuth(account='a@b.c', authType='passwd', password='123456')
    cookies, errStr = auth.auth()
    print(cookies)

    print('\nTest email')
    auth = msAuth(account='a@b.c', authType='email')
    auth.auth()
    code = input('input code:')
    cookies, errStr = auth.authEmail(code)
    print(cookies)

    print('\nTest device')
    auth = msAuth(account='a@b.c', authType='device')
    auth.auth()
    print(auth.getCode())
    cookies, errStr = auth.authDevice()
    print(cookies)
