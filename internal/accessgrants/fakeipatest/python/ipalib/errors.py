"""The few ipalib.errors classes the observer's failure classification meets."""


class PublicError(Exception):
    pass


class AuthenticationError(PublicError):
    pass


class KerberosError(AuthenticationError):
    pass


class NetworkError(PublicError):
    pass


class ACIError(PublicError):
    pass
