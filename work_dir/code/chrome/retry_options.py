"""
https://github.com/inyutin/aiohttp_retry/blob/master/aiohttp_retry/retry_options.py
"""

import abc
import random
from typing import Awaitable, Callable, Iterable

import ssl
import httpx


EvaluateResponseCallbackType = Callable[[httpx.Response], Awaitable[bool]]


class RetryOptionsBase:

    def __init__(
        self,
        attempts: int = 3,
        statuses: Iterable[int] | None = None,
        exceptions: Iterable[type[Exception]] | None = None,
        methods: Iterable[str] | None = None,
        *,
        retry_all_server_errors: bool = True,
        evaluate_response_callback: EvaluateResponseCallbackType | None = None,
    ) -> None:
        """
        :param attempts: How many times we should retry
        :param statuses: On which statuses we should retry
        :param exceptions: On which exceptions we should retry, by default:
        ssl.SSLError, httpx.RequestError, httpx.TransportError
        :param methods: On which HTTP methods we should retry
        :param retry_all_server_errors: If should retry all 500 errors or not
        :param evaluate_response_callback: a callback that will run on response to decide if retry
        """
        self.attempts: int = attempts
        if statuses is None:
            statuses = set()
        self.statuses: Iterable[int] = statuses

        if exceptions is None:
            exceptions = {ssl.SSLError, httpx.RequestError, httpx.TransportError}
        self.exceptions: Iterable[type[Exception]] = exceptions

        if methods is None:
            methods = {"HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST", "CONNECT", "PATCH"}
        self.methods: Iterable[str] = {method.upper() for method in methods}

        self.retry_all_server_errors = retry_all_server_errors
        self.evaluate_response_callback = evaluate_response_callback

    @abc.abstractmethod
    def get_timeout(self, attempt: int, response: httpx.Response | None = None) -> float:
        raise NotImplementedError


class ExponentialRetry(RetryOptionsBase):
    def __init__(
        self,
        *args,
        start_timeout: float = 0.1,
        max_timeout:   float = 30.0,
        factor:        float = 2.0,
        **kwargs,
    ) -> None:
        """
        :param start_timeout: Base timeout time, then it exponentially grow
        :param max_timeout: Max possible timeout between tries
        :param factor: How much we increase timeout each time
        """
        super().__init__(*args, **kwargs)
        self._start_timeout = start_timeout
        self._max_timeout = max_timeout
        self._factor = factor

    def get_timeout(
        self,
        attempt: int,
        response: httpx.Response | None = None,
    ) -> float:
        """Return timeout with exponential backoff."""
        timeout = self._start_timeout * (self._factor**attempt)
        return min(timeout, self._max_timeout)


class RandomRetry(RetryOptionsBase):
    def __init__(
        self,
        *args,
        min_timeout: float = 0.1,
        max_timeout: float = 3.0,
        random_func: Callable[[], float] = random.random,
        **kwargs,
    ) -> None:
        """
        :param min_timeout: Minimum possible timeout
        :param max_timeout: Maximum possible timeout between tries
        :param random_func: Random number generator
        """
        super().__init__(*args, **kwargs)
        self.min_timeout = min_timeout
        self.max_timeout = max_timeout
        self.random = random_func

    def get_timeout(
        self,
        attempt: int,
        response: httpx.Response | None = None,
    ) -> float:
        """Generate random timeouts."""
        return self.min_timeout + self.random() * (self.max_timeout - self.min_timeout)
