class APIException(Exception):
    def __init__(self, msg: str, code: int = 500) -> None:
        self.message = msg
        self.code = code
