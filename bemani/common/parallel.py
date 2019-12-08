import concurrent.futures
from typing import Any, Callable, List, TypeVar

T = TypeVar('T')


class Parallel:
    """
    Utilities for executing parallel operations. This is used as a convenience
    so that we don't have to plumb async/await support (yuck) through the network,
    but we can still make multiple queries at once to remote services and the DB.
    """

    @staticmethod
    def execute(lambdas: List[Callable[[], Any]]) -> List[Any]:
        """
        Given a list of callables, execute them and return a list of their returns.
        Guarantees order of return based on order of callable.
        """

        if len(lambdas) == 0:
            return []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(lambdas)) as executor:
            futures = {executor.submit(lambdas[pos]): pos for pos in range(len(lambdas))}
            results = []  # List: Tuple[Any, int]

            for future in concurrent.futures.as_completed(futures):
                pos = futures[future]
                data = future.result()
                results.append((data, pos))

            return [r[0] for r in sorted(results, key=lambda r: r[1])]

    @staticmethod
    def map(lam: Callable[[T], Any], params: List[T]) -> List[Any]:
        """
        Given a callable and a list of params, executes that callable with each set
        of params in the list and returns a list of their returns. Guarantees order
        of return.
        """

        if len(params) == 0:
            return []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(params)) as executor:
            futures = {executor.submit(lam, params[pos]): pos for pos in range(len(params))}
            results = []  # List: Tuple[Any, int]

            for future in concurrent.futures.as_completed(futures):
                pos = futures[future]
                data = future.result()
                results.append((data, pos))

            return [r[0] for r in sorted(results, key=lambda r: r[1])]

    @staticmethod
    def call(lambdas: 'List[Callable[..., Any]]', *params: Any) -> List[Any]:
        """
        Given a list of callables and zero or more params, calls each callable in
        parallel with the params specified. Essentially a map of params to multiple
        callables in parallel. Returns a list of returns, garanteed to be in the
        same order as the lambdas.
        """

        if len(lambdas) == 0:
            return []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(lambdas)) as executor:
            futures = {executor.submit(lambdas[pos], *params): pos for pos in range(len(lambdas))}
            results = []  # List: Tuple[Any, int]

            for future in concurrent.futures.as_completed(futures):
                pos = futures[future]
                data = future.result()
                results.append((data, pos))

            return [r[0] for r in sorted(results, key=lambda r: r[1])]

    @staticmethod
    def flatten(lists: List[List[Any]]) -> List[Any]:
        """
        Convenience function that probably exists in functools, but whatever.
        Takes a list of lists, and returns a list made of all those lists
        joined together.
        """

        return [item for sublist in lists for item in sublist]
