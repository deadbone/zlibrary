import aiohttp
import asyncio

from aiohttp_socks import ChainProxyConnector

from .exception import LoopError, SecurityCheckError
from .logger import logger
from aiohttp.abc import AbstractCookieJar
from typing import Tuple


HEAD = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
}


TIMEOUT = aiohttp.ClientTimeout(total=180, connect=0, sock_connect=120, sock_read=180)

HEAD_TIMEOUT = aiohttp.ClientTimeout(total=4, connect=0, sock_connect=4, sock_read=4)

SECURITY_CHECK_MARKERS = (
    "checking your browser",
    "cf-browser-verification",
    "attention required",
    "cloudflare",
    "ddos-guard",
    "please verify you are a human",
    "just a moment",
    "enable javascript and cookies",
)


def _detect_security_check(body: str) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in SECURITY_CHECK_MARKERS)


async def GET_request(url, cookies=None, proxy_list=None, headers=None) -> str:
    try:
        async with aiohttp.ClientSession(
            headers=headers or HEAD,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            cookies=cookies,
            timeout=TIMEOUT,
            connector=ChainProxyConnector.from_urls(proxy_list) if proxy_list else None,
        ) as sess:
            logger.info("GET %s" % url)
            async with sess.get(url) as resp:
                body = await resp.text()
                if _detect_security_check(body):
                    raise SecurityCheckError(
                        "Security check page returned from %s. "
                        "Use a verified mirror, onion access, or supply clearance cookies/headers."
                        % url
                    )
                return body
    except asyncio.exceptions.CancelledError:
        raise LoopError("Asyncio loop has been closed before request could finish.")


async def GET_request_cookies(
    url, cookies=None, proxy_list=None, headers=None
) -> Tuple[str, AbstractCookieJar]:
    try:
        async with aiohttp.ClientSession(
            headers=headers or HEAD,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            cookies=cookies,
            timeout=TIMEOUT,
            connector=ChainProxyConnector.from_urls(proxy_list) if proxy_list else None,
        ) as sess:
            logger.info("GET %s" % url)
            async with sess.get(url) as resp:
                body = await resp.text()
                if _detect_security_check(body):
                    raise SecurityCheckError(
                        "Security check page returned from %s. "
                        "Use a verified mirror, onion access, or supply clearance cookies/headers."
                        % url
                    )
                return (body, sess.cookie_jar)
    except asyncio.exceptions.CancelledError:
        raise LoopError("Asyncio loop has been closed before request could finish.")


async def POST_request(url, data, proxy_list=None, headers=None):
    try:
        async with aiohttp.ClientSession(
            headers=headers or HEAD,
            timeout=TIMEOUT,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            connector=ChainProxyConnector.from_urls(proxy_list) if proxy_list else None,
        ) as sess:
            logger.info("POST %s" % url)
            async with sess.post(url, data=data) as resp:
                body = await resp.text()
                if _detect_security_check(body):
                    raise SecurityCheckError(
                        "Security check page returned from %s. "
                        "Use a verified mirror, onion access, or supply clearance cookies/headers."
                        % url
                    )
                return (body, sess.cookie_jar)
    except asyncio.exceptions.CancelledError:
        raise LoopError("Asyncio loop has been closed before request could finish.")


async def HEAD_request(url, proxy_list=None, headers=None):
    try:
        async with aiohttp.ClientSession(
            headers=headers or HEAD,
            timeout=HEAD_TIMEOUT,
            connector=ChainProxyConnector.from_urls(proxy_list) if proxy_list else None,
        ) as sess:
            logger.info("Checking connectivity of %s..." % url)
            async with sess.head(url) as resp:
                return resp.status
    except asyncio.exceptions.CancelledError:
        raise LoopError("Asyncio loop has been closed before request could finish.")
    except asyncio.exceptions.TimeoutError:
        return 0
