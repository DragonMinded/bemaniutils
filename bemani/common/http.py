from typing import Any, Dict, List, Optional, Tuple


class HTTP:
    @staticmethod
    def parse(data: bytes, request: bool=False, response: bool=False) -> Optional[Dict[str, Any]]:
        """
        A very lazy and hastily coded HTTP parser.

        Assumes that data is a valid HTTP stream and just tokenizes relevant pieces.
        This can probably be made far more robust by scrapping it and using flask or
        another real parser. However, it does the job.

        Parameters:
            data - A string blob that represents an HTTP request
            request - Set to true if this is expected to be a request
            response - Set to true if this is expected to be a response

        Returns a dictionary containing:
            version - HTTP version
            headers - Dictionary of headers keyed by header name
            data - Post body in unmolested form
            uri - Requested URI when this is a request
            method - Requested method on URI when this is a request
            code - HTTP response code when this is a response
        """
        try:
            # Try to get the headers and post body as two separate elemenst
            binary_headers, data = data.split(b"\r\n\r\n", 1)
        except ValueError:
            # Can't even separate header from post body
            return None

        # Split headers individually
        headerlist = binary_headers.split(b"\r\n")

        try:
            if request:
                # Remove the first header as this is the HTTP request
                method, uri, version = headerlist.pop(0).split(b' ', 2)
            elif response:
                # Remove the first header as this is the HTTP response
                version, code, error = headerlist.pop(0).split(b' ', 2)
            else:
                raise Exception("Logic error!")
        except ValueError:
            # Can't parse the headers returned
            return None

        headers: Dict[str, str] = {}
        preserved: List[Tuple[str, str]] = []

        # This is lazy because we can have multiple values, but whatever, it works
        for header in headerlist:
            name, info = header.split(b":", 1)
            key = name.decode('ascii').lower()
            value = info.decode('ascii').strip()
            headers[key] = value
            preserved.append((key, value))

        # Cap post body to length if we have a content-length header
        if 'content-length' in headers:
            data = data[:int(headers['content-length'])]
            valid = len(data) == int(headers['content-length'])
        elif 'transfer-encoding' in headers and headers['transfer-encoding'] == 'chunked':
            real_data = b''

            while True:
                try:
                    size_bytes, rest = data.split(b"\r\n", 1)
                except ValueError:
                    # Not enough values to unpack
                    size_bytes = b'0'

                size = int(size_bytes, 16)

                if size == 0:
                    # End of chunks
                    break

                # Grab the real data
                real_data = real_data + rest[:size]

                # Skip past data and \r\n
                data = rest[(size + 2):]

            data = real_data
            valid = True
        else:
            valid = True

        if request:
            return {
                'method': method.decode('ascii').lower(),
                'uri': uri.decode('ascii'),
                'version': version.decode('ascii'),
                'headers': headers,
                'preserved_headers': preserved,
                'data': data,
                'valid': valid,
            }
        elif response:
            return {
                'code': code.decode('ascii'),
                'version': version.decode('ascii'),
                'error': error.decode('ascii'),
                'headers': headers,
                'preserved_headers': preserved,
                'data': data,
                'valid': valid,
            }
        else:
            return None

    @staticmethod
    def generate(parsed_headers: Dict[str, Any], data: bytes, request: bool=False, response: bool=False) -> bytes:
        """
        A very lazy and hastily coded HTTP packet generator.

        Parameters:
            parsed_headers - A dictionary of headers to include
            data - Bytes which should make up the body of the HTTP packet
            request - Set to True if this is a request
            response - Set to True if this is a response

        Returns:
            Binary data which can be sent over the wire to a HTTP server.
        """
        out = []

        # Add first part of header
        if request:
            out.append(f'{parsed_headers["method"]} {parsed_headers["uri"]} {parsed_headers["version"]}')
        elif response:
            out.append(f'{parsed_headers["version"]} {parsed_headers["code"]} {parsed_headers["error"]}')
        else:
            raise Exception("Logic error!")

        # Add the rest of the headers
        for header in parsed_headers['preserved_headers']:
            name, value = header
            if name.lower() == 'content-length':
                # Fix this
                value = len(data)
            elif name.lower() == 'transfer-encoding':
                # Either we support and strip this, or error!
                if value.lower() == 'chunked':
                    # We support parsing this, but aren't going to re-generate
                    continue
                else:
                    # Woah, can't figure this out!
                    raise Exception(f"Unknown transfer-encodign {value}")

            out.append(f"{name}: {value}")

        # Concatenate it with the binary data
        return "\r\n".join(out).encode('ascii') + b'\r\n\r\n' + data
