import argparse
import requests
import socket
import yaml
from flask import Flask, Response, request
from typing import Any, Dict, Optional
import urllib.parse as urlparse

from bemani.protocol import EAmuseProtocol, Node

# Application configuration
app = Flask(__name__)
config: Dict[str, Any] = {}


def modify_request(config: Dict[str, Any], req_body: Node) -> Optional[Node]:
    # Not sure if there's any reason to modify requests, but its plumbed
    return None


def modify_response(config: Dict[str, Any], resp_body: Node) -> Optional[Node]:
    # Figure out if we need to modify anything in the response
    if resp_body.name != "response":
        # Not what we expected, bail
        return None

    # Now we get to the meat of packet detection
    body = resp_body.children[0]

    # Is this a services packet? We need to modify this to point the rest of the
    # game packets at this proxy :(
    if body.name == "services":
        for child in body.children:
            if child.name == "item":
                if child.attribute("name") == "ntp":
                    # Don't override this
                    continue
                elif child.attribute("name") == "keepalive":
                    # Completely rewrite to point at the proxy server, otherwise if we're proxying
                    # to a local backend, we will end up giving out a local address and we will get
                    # Network NG.
                    address = socket.gethostbyname(config["keepalive"])
                    child.set_attribute(
                        "url",
                        f"http://{address}/core/keepalive?pa={address}&ia={address}&ga={address}&ma={address}&t1=2&t2=10",
                    )
                else:
                    # Get netloc to replace
                    url = urlparse.urlparse(child.attribute("url"))
                    defaultport = {
                        "http": 80,
                        "https": 443,
                    }.get(url.scheme, 0)
                    if config["local_port"] != defaultport:
                        new_url = child.attribute("url").replace(
                            url.netloc, f'{config["local_host"]}:{config["local_port"]}'
                        )
                    else:
                        new_url = child.attribute("url").replace(
                            url.netloc, f'{config["local_host"]}'
                        )
                    child.set_attribute("url", new_url)

        return resp_body

    return None


@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def receive_healthcheck(path: str) -> Response:
    if "*" in config["remote"]:
        remote_host = config["remote"]["*"]["host"]
        remote_port = config["remote"]["*"]["port"]
    else:
        return Response("No route for default PCBID", 500)

    actual_path = f"/{path}"
    if request.query_string is not None and len(request.query_string) > 0:
        actual_path = actual_path + f'?{request.query_string.decode("ascii")}'

    # Make request to foreign service, using the same parameters
    r = requests.get(
        f"http://{remote_host}:{remote_port}{actual_path}",
        timeout=config["timeout"],
        allow_redirects=False,
    )

    headers = {}
    for header in ["Location"]:
        if header in r.headers:
            headers[header] = r.headers[header]

    return Response(r.content, r.status_code, headers)


@app.route("/", defaults={"path": ""}, methods=["POST"])
@app.route("/<path:path>", methods=["POST"])
def receive_request(path: str) -> Response:
    # First, parse the packet itself
    client_proto = EAmuseProtocol()
    server_proto = EAmuseProtocol()
    remote_address = request.headers.get("X-Remote-Address", None)
    request_compression = request.headers.get("X-Compress", None)
    request_encryption = request.headers.get("X-Eamuse-Info", None)
    request_client = request.headers.get("User-Agent", None)

    actual_path = f"/{path}"
    if request.query_string is not None and len(request.query_string) > 0:
        actual_path = actual_path + f'?{request.query_string.decode("ascii")}'

    if config["verbose"]:
        print(f"HTTP request for URI {actual_path}")
        print(f"Compression is {request_compression}")
        print(f"Encryption key is {request_encryption}")

    req = client_proto.decode(
        request_compression,
        request_encryption,
        request.data,
    )

    if req is None:
        # Nothing to do here
        return Response("Unrecognized packet!", 500)

    if config["verbose"]:
        print("Original request to server:")
        print(req)

    # Grab PCBID for directing to mulitple servers
    pcbid = req.attribute("srcid")
    if pcbid in config["remote"]:
        remote_host = config["remote"][pcbid]["host"]
        remote_port = config["remote"][pcbid]["port"]
    elif "*" in config["remote"]:
        remote_host = config["remote"]["*"]["host"]
        remote_port = config["remote"]["*"]["port"]
    else:
        return Response(f"No route for PCBID {pcbid}", 500)

    modified_request = modify_request(config, req)
    if modified_request is None:
        # Return the original binary data instead of re-encoding it
        # to the exact same thing.
        req_binary = request.data
    else:
        if config["verbose"]:
            print("Modified request to server:")
            print(modified_request)

        # Re-encode the modified packet
        req_binary = server_proto.encode(
            request_compression,
            request_encryption,
            modified_request,
            client_proto.last_text_encoding,
            client_proto.last_packet_encoding,
        )

    # Set up custom headers for remote request.
    headers = {
        # For lobby functionality, make sure the request receives
        # the original IP address
        "X-Remote-Address": remote_address or request.remote_addr,
        # Some remote servers can be somewhat buggy, so we make sure
        # to specify a range of encodings.
        "Accept-Encoding": "identity, deflate, compress, gzip",
    }

    # Copy over required headers that are sent by game client.
    if request_compression:
        headers["X-Compress"] = request_compression
    else:
        headers["X-Compress"] = "none"
    if request_encryption:
        headers["X-Eamuse-Info"] = request_encryption

    # Make sure to copy the user agent as well.
    if request_client is not None:
        headers["User-Agent"] = request_client

    # Make request to foreign service, using the same parameters
    prep_req = requests.Request(
        "POST",
        url=f"http://{remote_host}:{remote_port}{actual_path}",
        headers=headers,
        data=req_binary,
    ).prepare()
    sess = requests.Session()
    r = sess.send(prep_req, timeout=config["timeout"])

    if r.status_code != 200:
        # Failed on remote side
        return Response("Failed to get response!", 500)

    # Decode response, for modification if necessary
    response_compression = r.headers.get("X-Compress", None)
    response_encryption = r.headers.get("X-Eamuse-Info", None)
    resp = server_proto.decode(
        response_compression,
        response_encryption,
        r.content,
    )

    if resp is None:
        # Nothing to do here
        return Response("Unrecognized packet!", 500)

    if config["verbose"]:
        print("Original response from server:")
        print(resp)

    modified_response = modify_response(config, resp)
    if modified_response is None:
        # Return the original response data instead of re-encoding it
        # to the exact same thing.
        resp_binary = r.content
    else:
        if config["verbose"]:
            print("Modified response from server:")
            print(modified_response)

        # Re-encode the modified packet
        resp_binary = client_proto.encode(
            response_compression,
            response_encryption,
            modified_response,
        )

    # Some old clients are case sensitive, so be careful to capitalize
    # these responses here.
    flask_resp = Response(resp_binary)
    if response_compression is not None:
        flask_resp.headers["X-Compress"] = response_compression
    if response_encryption is not None:
        flask_resp.headers["X-Eamuse-Info"] = response_encryption
    return flask_resp


def load_proxy_config(filename: str) -> None:
    global config

    config_data = yaml.safe_load(open(filename))
    if "pcbid" in config_data and config_data["pcbid"] is not None:
        for pcbid in config_data["pcbid"]:
            remote_name = config_data["pcbid"][pcbid]
            remote_config = config_data["remote"][remote_name]
            config["remote"][pcbid] = remote_config


def load_config(filename: str) -> None:
    global config

    config_data = yaml.safe_load(open(filename))
    config.update(
        {
            "local_host": config_data["local"]["host"],
            "local_port": config_data["local"]["port"],
            "verbose": config_data.get("verbose", False),
            "timeout": config_data.get("timeout", 30),
            "keepalive": config_data.get("keepalive", "localhost"),
        }
    )

    if "default" in config_data:
        remote_config = config_data["remote"][config_data["default"]]
        config.update(
            {
                "remote": {
                    "*": remote_config,
                },
            }
        )
    else:
        config.update({"remote": {}})

    if "pcbid" in config_data and config_data["pcbid"] is not None:
        load_proxy_config(filename)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A utility to MITM non-SSL eAmusement connections."
    )
    parser.add_argument(
        "-p",
        "--port",
        help="Port to listen on. Defaults to 9090",
        type=int,
        default=9090,
    )
    parser.add_argument(
        "-a",
        "--address",
        help="Address to listen on. Defaults to all addresses",
        type=str,
        default="0.0.0.0",
    )
    parser.add_argument(
        "-r",
        "--real-address",
        help="Real address we are listening on (for NAT and such)",
        type=str,
        default="127.0.0.1",
    )
    parser.add_argument(
        "-q", "--remote-port", help="Port to connect to.", type=int, required=True
    )
    parser.add_argument(
        "-b", "--remote-address", help="Address to connect to.", type=str, required=True
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Configuration file for PCBID to remote server mapping.",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-k",
        "--keepalive",
        help="Keepalive domain to advertise. Defaults to localhost",
        type=str,
        default="localhost",
    )
    parser.add_argument(
        "-v", "--verbose", help="Display verbose packet info.", action="store_true"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Timeout (in seconds) for proxy requests. Defaults to 30 seconds.",
        type=int,
        default=30,
    )
    args = parser.parse_args()

    config.update(
        {
            "local_host": args.real_address,
            "local_port": args.port,
            "remote": {
                "*": {
                    "host": args.remote_address,
                    "port": args.remote_port,
                },
            },
            "verbose": args.verbose,
            "timeout": args.timeout,
            "keepalive": args.keepalive,
        }
    )

    # Fill in remote addresses for PCBIDs we should redirect to a non-default server
    if args.config is not None:
        load_proxy_config(args.config)

    app.run(host="0.0.0.0", port=args.port, debug=True)
