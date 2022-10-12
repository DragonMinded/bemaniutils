#! /usr/bin/env python3
import argparse
import json
import requests
import sys
from typing import Dict, List, Any, Optional


class APIClient:
    API_VERSION = 'v1'

    def __init__(self, base_uri: str, token: str) -> None:
        self.base_uri = base_uri
        self.token = token

    def exchange_data(self, request_uri: str, request_args: Dict[str, Any]) -> Dict[str, Any]:
        if self.base_uri[-1:] != '/':
            uri = '{}/{}'.format(self.base_uri, request_uri)
        else:
            uri = '{}{}'.format(self.base_uri, request_uri)

        headers = {
            'Authorization': 'Token {}'.format(self.token),
            'Content-Type': 'application/json; charset=utf-8',
        }
        data = json.dumps(request_args).encode('utf8')

        r = requests.request(
            'GET',
            uri,
            headers=headers,
            data=data,
            allow_redirects=False,
        )

        if r.headers['content-type'] != 'application/json; charset=utf-8':
            raise Exception('API returned invalid content type \'{}\'!'.format(r.headers['content-type']))

        jsondata = r.json()

        if r.status_code == 200:
            return jsondata

        if 'error' not in jsondata:
            raise Exception('API returned error code {} but did not include \'error\' attribute in response JSON!'.format(r.status_code))
        error = jsondata['error']

        if r.status_code == 401:
            raise Exception('The API token used is not authorized against the server!')
        if r.status_code == 404:
            raise Exception('The server does not support this game/version or request object and returned \'{}\''.format(error))
        if r.status_code == 405:
            raise Exception('The server did not recognize the request and returned \'{}\''.format(error))
        if r.status_code == 500:
            raise Exception('The server had an error processing the request and returned \'{}\''.format(error))
        if r.status_code == 501:
            raise Exception('The server does not support this version of the API!')
        raise Exception('The server returned an invalid status code {}!'.format(r.status_code))

    def info_exchange(self) -> None:
        resp = self.exchange_data('', {})
        print('Server name: {}'.format(resp['name']))
        print('Server admin email: {}'.format(resp['email']))
        print('Server supported versions: {}'.format(', '.join(resp['versions'])))

    def __id_check(self, idtype: str, ids: List[str]) -> None:
        if idtype not in ['card', 'song', 'instance', 'server']:
            raise Exception('Invalid ID type provided!')
        if idtype == 'card' and len(ids) == 0:
            raise Exception('Invalid number of IDs given!')
        if idtype == 'song' and len(ids) not in [1, 2]:
            raise Exception('Invalid number of IDs given!')
        if idtype == 'instance' and len(ids) != 3:
            raise Exception('Invalid number of IDs given!')
        if idtype == 'server' and len(ids) != 0:
            raise Exception('Invalid number of IDs given!')

    def records_exchange(self, game: str, version: str, idtype: str, ids: List[str], since: Optional[int], until: Optional[int]) -> None:
        self.__id_check(idtype, ids)
        params = {
            'ids': ids,
            'type': idtype,
            'objects': ['records'],
        }  # type: Dict[str, Any]
        if since is not None:
            params['since'] = since
        if until is not None:
            params['until'] = until
        resp = self.exchange_data(
            '{}/{}/{}'.format(self.API_VERSION, game, version),
            params,
        )
        print(json.dumps(resp['records'], indent=4))

    def profile_exchange(self, game: str, version: str, idtype: str, ids: List[str]) -> None:
        self.__id_check(idtype, ids)
        resp = self.exchange_data(
            '{}/{}/{}'.format(self.API_VERSION, game, version),
            {
                'ids': ids,
                'type': idtype,
                'objects': ['profile'],
            },
        )
        print(json.dumps(resp['profile'], indent=4))

    def statistics_exchange(self, game: str, version: str, idtype: str, ids: List[str]) -> None:
        self.__id_check(idtype, ids)
        resp = self.exchange_data(
            '{}/{}/{}'.format(self.API_VERSION, game, version),
            {
                'ids': ids,
                'type': idtype,
                'objects': ['statistics'],
            },
        )
        print(json.dumps(resp['statistics'], indent=4))

    def catalog_exchange(self, game: str, version: str) -> None:
        resp = self.exchange_data(
            '{}/{}/{}'.format(self.API_VERSION, game, version),
            {
                'ids': [],
                'type': 'server',
                'objects': ['catalog'],
            },
        )
        print(json.dumps(resp['catalog'], indent=4))


def main():
    # Global arguments
    parser = argparse.ArgumentParser(description='A sample API client for an e-AMUSEMENT API provider.')
    parser.add_argument('-t', '--token', type=str, required=True, help='The authorization token for speaing to the API.')
    parser.add_argument('-b', '--base', type=str, required=True, help='Base URI to connect to for all requests.')
    subparser = parser.add_subparsers(dest='request')

    # Info request
    subparser.add_parser('info')

    # Score request
    record_parser = subparser.add_parser('records')
    record_parser.add_argument('-g', '--game', type=str, required=True, help='The game we want to look records up for.')
    record_parser.add_argument('-v', '--version', type=str, required=True, help='The version we want to look records up for.')
    record_parser.add_argument('-t', '--type', type=str, required=True, choices=['card', 'song', 'instance', 'server'], help='The type of ID used to look up records.')
    record_parser.add_argument('-s', '--since', metavar='TIMESTAMP', default=None, type=int, help='Only load records updated since TIMESTAMP')
    record_parser.add_argument('-u', '--until', metavar='TIMESTAMP', default=None, type=int, help='Only load records updated before TIMESTAMP')
    record_parser.add_argument('id', metavar='ID', nargs='*', type=str, help='The ID we will look up records for.')

    # Profile request
    profile_parser = subparser.add_parser('profile')
    profile_parser.add_argument('-g', '--game', type=str, required=True, help='The game we want to look profiles up for.')
    profile_parser.add_argument('-v', '--version', type=str, required=True, help='The version we want to look profiles up for.')
    profile_parser.add_argument('-t', '--type', type=str, required=True, choices=['card', 'server'], help='The type of ID used to look up profiles.')
    profile_parser.add_argument('id', metavar='ID', nargs='*', type=str, help='The ID we will look up profiles for.')

    # Statistics request
    statistic_parser = subparser.add_parser('statistics')
    statistic_parser.add_argument('-g', '--game', type=str, required=True, help='The game we want to look statistics up for.')
    statistic_parser.add_argument('-v', '--version', type=str, required=True, help='The version we want to look statistics up for.')
    statistic_parser.add_argument('-t', '--type', type=str, required=True, choices=['card', 'song', 'instance', 'server'], help='The type of ID used to look up statistics.')
    statistic_parser.add_argument('id', metavar='ID', nargs='*', type=str, help='The ID we will look up statistics for.')

    # Catalog request
    catalog_parser = subparser.add_parser('catalog')
    catalog_parser.add_argument('-g', '--game', type=str, required=True, help='The game we want to look catalog entries up for.')
    catalog_parser.add_argument('-v', '--version', type=str, required=True, help='The version we want to look catalog entries up for.')

    # Grab args
    args = parser.parse_args()
    client = APIClient(args.base, args.token)
    if args.request == 'info':
        client.info_exchange()
    elif args.request == 'records':
        client.records_exchange(
            args.game,
            args.version,
            args.type,
            args.id,
            args.since,
            args.until,
        )
    elif args.request == 'profile':
        client.profile_exchange(
            args.game,
            args.version,
            args.type,
            args.id,
        )
    elif args.request == 'statistics':
        client.statistics_exchange(
            args.game,
            args.version,
            args.type,
            args.id,
        )
    elif args.request == 'catalog':
        client.catalog_exchange(
            args.game,
            args.version,
        )
    else:
        raise Exception('Invalid request type {}!'.format(args.request))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
