from requests import request, Response, HTTPError
from urllib.parse import urljoin
import logging
import json
from datetime import datetime
from dateutil.parser import isoparse

from typing import Tuple, Any, List
import warnings

class RegistryExceptionBase(HTTPError):
    def __init__(self, response: Response):
        super().__init__("{} {}".format(response.status_code, response.reason), response=response)


class RegistryException(RegistryExceptionBase):
    def __init__(self, response: Response, code: str, message: str, detail):
        super().__init__(response=response)
        self.code = code
        self.message = message
        self.detail = detail

    def __str__(self):
        return "{}: {}".format(self.code, self.message)


class RegistryExceptionMultiple(RegistryExceptionBase):
    def __init__(self, response: Response, errors: List[RegistryException]):
        super().__init__(response=response)
        self.errors = errors

    def __str__(self):
        return "\n".join(map(str, self.errors))


class Manifest:
    """
    Class representing docker manifest
    """
    def __init__(self, content: dict, digest: str, repository: 'Repository'):
        self.content = content
        self.digest = digest
        self._repository = repository
        self._config = None
        self.references = set()

    @property
    def config(self) -> dict:
        if self._config is None:
            self._config = self._repository.blob(self.content["config"]["digest"])

        return self._config

    @property
    def created(self) -> datetime:
        return isoparse(self.config.get("created"))

    def delete(self) -> None:
        """
        Delete this manifest.
        """

        self._repository._client._http_response(self._repository._client._http_request(
            self._repository.V2_MANIFEST.format(name=self._repository.name, reference=self.digest),
            method="DELETE",
            logger=self._repository._log
        ), allowed_codes=(200, 202, ), logger=self._repository._log)

    def _add_reference(self, reference: str) -> None:
        self.references.add(reference)

    def __hash__(self) -> int:
        return hash(self.digest)

    def __eq__(self, other: 'Manifest') -> bool:
        if not isinstance(other, Manifest):
            raise TypeError("Can only compare to other Manifest instance.")

        return self.digest == other.digest

    def __repr__(self):
        return "Manifest('{}')".format(self.digest)


class Repository:
    """
    Class representing one Docker repository and operations that can be performend on top of it.
    """

    V2_TAG_LIST = "/v2/{name}/tags/list"
    V2_MANIFEST = "/v2/{name}/manifests/{reference}"
    V2_BLOB = "/v2/{name}/blobs/{digest}"

    def __init__(self, name: str, client: 'DockerRegistryClient'):
        self.name = name
        self._client = client
        self._log = self._client._log.getChild(self.name)
        self._manifests = {}

    def tags(self):
        content, _ = self._client._http_response(self._client._http_request(
            self.V2_TAG_LIST.format(name=self.name),
            logger=self._log
        ), logger=self._log)

        return content["tags"]

    def blob(self, digest: str) -> str:
        content, _ = self._client._http_response(self._client._http_request(
            self.V2_BLOB.format(name=self.name, digest=digest),
            logger=self._log
        ), logger=self._log)

        return content

    def manifest(self, reference: str):
        content, resp = self._client._http_response(self._client._http_request(
            self.V2_MANIFEST.format(name=self.name, reference=reference),
            logger=self._log
        ), logger=self._log)

        digest = resp.headers['docker-content-digest']
        if digest not in self._manifests:
            self._manifests[digest] = Manifest(content, digest, self)

        self._manifests[digest]._add_reference(reference)
        return self._manifests[digest]

    def __repr__(self):
        return "Repository('{}')".format(urljoin(self._client._host, "/"+self.name))


class DockerRegistryClient:
    """
    Simple Docker registry API client
    """
    V2_CATALOG = "/v2/_catalog"

    def __init__(self, hostname: str, verify_ssl: bool = True):
        self._host = hostname
        self._verify_ssl = verify_ssl
        self._log = logging.getLogger(self.__class__.__name__)

        if not self._verify_ssl:
            warnings.filterwarnings("ignore", module="urllib3")

    def _http_request(self, endpoint: str, method: str="GET", logger: logging.Logger=None) -> Response:
        if logger is None:
            logger = self._log

        url = urljoin(self._host, endpoint)

        logger.debug("{} {}".format(method, url))

        return request(method, url, headers={
            "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/json"
        }, verify=self._verify_ssl)

    def _http_response(self, resp: Response, allowed_codes=(200, ), logger: logging.Logger=None) -> Tuple[Any, Response]:
        if logger is None:
            logger = self._log

        try:
            content = resp.json()
        except ValueError as e:
            content = resp.content

        logger.debug("{} {}".format(resp.status_code, resp.reason))

        if resp.status_code in allowed_codes:
            return content, resp
        else:
            if not isinstance(content, dict):
                raise RegistryExceptionBase(response=resp)
            else:
                errors = content.get("errors", [])
                if len(errors) > 1:
                    raise RegistryExceptionMultiple(resp, map(
                        lambda err: RegistryException(resp, err["code"], err["message"], err["detail"]),
                        errors
                    ))
                elif len(errors) == 1:
                    err = errors[0]
                    raise RegistryException(resp, err["code"], err["message"], err["detail"])
                else:
                    raise RegistryExceptionBase(resp)

    def repository(self, name: str) -> Repository:
        return Repository(name, self)

    def repositories(self) -> List[Repository]:
        return list(map(
            lambda repo: Repository(repo, self),
            self._http_response(self._http_request(self.V2_CATALOG))[0]["repositories"]
        ))
