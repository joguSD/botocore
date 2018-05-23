import logging
import socket

from urllib3 import PoolManager
from urllib3.exceptions import NewConnectionError

from botocore.vendored import six
from botocore.awsrequest import AWSResponse
from botocore.compat import filter_ssl_warnings
from botocore.exceptions import ConnectionClosedError, EndpointConnectionError

try:
    from urllib3.contrib import pyopenssl
    pyopenssl.extract_from_urllib3()
except ImportError:
    pass

filter_ssl_warnings()
logger = logging.getLogger(__name__)


class Urllib3Session(object):
    def __init__(self,
                 verify=True,
                 proxies=None,
                 timeout=None,
                 max_pool_connections=None,
    ):
        self.http_pool = PoolManager()
        self.verify = verify
        self.proxies = proxies
        self.timeout = timeout
        self.max_pool_connections = max_pool_connections

    def _verify_cert(self, conn, url, verify, cert):
        if url.lower().startswith('https') and verify:

            cert_loc = None

            # Allow self-specified cert location.
            if verify is not True:
                cert_loc = verify

            if not cert_loc:
                import certifi
                cert_loc = certifi.where()

            if not cert_loc:
                raise Exception("Could not find a suitable SSL CA certificate bundle.")

            conn.cert_reqs = 'CERT_REQUIRED'
            conn.ca_certs = cert_loc
        else:
            conn.cert_reqs = 'CERT_NONE'
            conn.ca_certs = None

        if cert:
            from botocore.vendored.requests.utils import basestring
            if not isinstance(cert, basestring):
                conn.cert_file = cert[0]
                conn.key_file = cert[1]
            else:
                conn.cert_file = cert

    def send(self, request, streaming=False):
        try:
            conn = self.http_pool.connection_from_url(request.url)
            self._verify_cert(conn, request.url, self.verify, None)
            urllib_response = conn.urlopen(
                method=request.method,
                url=request.url,
                body=request.body,
                headers=request.headers,
                retries=False,
                assert_same_host=False,
                preload_content=False,
                decode_content=False,
            )

            http_response = AWSResponse()
            http_response.url = request.url
            http_response.status_code = urllib_response.status
            http_response.headers = dict(urllib_response.headers.items())
            http_response.raw = urllib_response

            if not streaming:
                # Cause the raw stream to be exhausted immediatly
                http_response.content

            # We techniclly don't use any of these
            # http_response.connection = conn
            # http_response.encoding = None  # TODO get from headers?
            # http_response.request = request
            # http_response.reason = urllib_response.reason

            return http_response
        except (NewConnectionError, socket.gaierror) as e:
            raise EndpointConnectionError(endpoint_url=request.url, error=e)
        except six.moves.http_client.BadStatusLine as e:
            raise ConnectionClosedError(
                request=request,
                endpoint_url=request.url
            )
