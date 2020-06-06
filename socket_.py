import socket
import logging
from datetime import datetime

from typing import Tuple

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Socket Sandbox')

DATETIME_FORMAT = "%d-%m-%Y %H:%M:%S"

URLS = {
    '/': '<h1>I N D E X</h1>'
}


def get_current_utc_time() -> str:
    return datetime.utcnow().strftime(DATETIME_FORMAT)


def get_headers_dict(raw_headers: list) -> dict:
    headers = {}

    for header_string in raw_headers:
        if header_string.strip():
            key, value = list(map(str.strip, header_string.split(': ')))
            headers = {**headers, key: value,}

    return headers


def parse_request(request: bytes, request_ip: str) -> Tuple[str, ...]:
    request = request.decode('utf-8')
    parsed = request.split('\n')
    method, url, *protocol = list(map(str.strip, parsed.pop(0).split(' ')))

    headers = get_headers_dict(parsed)  # Shiny headers dict, but useless for now

    logger.info(f'\t{get_current_utc_time()} > {request_ip} [{method}] - "{url}" {protocol[-1]}')

    return method, url


def create_headers(method: str, url: str) -> Tuple[str, int]:
    if method != 'GET':
        return 'HTTP/1.1 405 Method not allowed\n\n', 405

    if url not in URLS:
        return 'HTTP/1.1 404 Page not found\n\n', 404

    return 'HTTP/1.1 200 OK\n\n', 200


def create_body(status_code, url) -> str:
    if status_code == 404:
        return '<h3>404 Page Not Found</h3>'

    if status_code == 404:
        return '<h3>404 Method Not Allowed</h3>'

    return URLS.get(url)


def create_response(method, url) -> bytes:
    headers, status_code = create_headers(method, url)
    body = create_body(status_code, url)

    return (headers + body).encode('utf-8')


def run_server():
    server_socket = socket.socket(
        socket.AF_INET,  # Protocol IPv4
        socket.SOCK_STREAM  # Protocol TCP
    )  # -> SOCKET

    # Setting for avoiding error 'Address already in use'
    # Not for production of course!

    # server_socket.setsockopt(
    #     socket.SOL_SOCKET,  # Level of options - this socket
    #     socket.SO_REUSEADDR,  # Re-use IP address
    #     1  # True
    # )

    server_socket.bind(('127.0.0.1', 8008))  # Bind Address and port
    server_socket.listen()  # Listening. . .
    logger.debug(f'\t{get_current_utc_time()} Server socket is listening. . .')

    while True:
        client_socket, address = server_socket.accept()
        request = client_socket.recv(768)

        method, url = parse_request(request, ':'.join(list(map(str, address))))
        response = create_response(method, url)

        # Respond to client
        client_socket.sendall(response)
        client_socket.close()


if __name__ == '__main__':
    run_server()
