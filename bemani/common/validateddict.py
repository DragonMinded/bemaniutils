from typing import Optional, List, Dict, Any


def intish(val: Any, base: int=10) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val, base)
    except ValueError:
        return None


class ValidatedDict(dict):
    """
    Helper class which gives a Dict object superpowers. Allows stores and loads to be
    validated so you only ever update when given good data, and only ever return
    non-default values when data is good. Used primarily for storing data pulled
    directly from game responses, or reading data to echo to a game.

    All of the get functions will verify that the attribute exists and is the right
    type. If it is not, the default value is returned.

    all of the set functions will verify that the to-be-stored value matches the
    type. If it does not, the value is not updated.
    """

    def get_int(self, name: str, default: int=0) -> int:
        """
        Given the name of a value, return an integer stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't an integer.

        Returns:
            An integer.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != int:
            return default
        return val

    def get_float(self, name: str, default: float=0.0) -> float:
        """
        Given the name of a value, return a float stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't a float.

        Returns:
            A float.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != float:
            return default
        return val

    def get_bool(self, name: str, default: bool=False) -> bool:
        """
        Given the name of a value, return a boolean stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't a boolean.

        Returns:
            A boolean.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != bool:
            return default
        return val

    def get_str(self, name: str, default: str='') -> str:
        """
        Given the name of a value, return string stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't a string.

        Returns:
            A string.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != str:
            return default
        return val

    def get_bytes(self, name: str, default: bytes=b'') -> bytes:
        """
        Given the name of a value, return bytes stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't bytes.

        Returns:
            A bytestring.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != bytes:
            return default
        return val

    def get_int_array(self, name: str, length: int, default: Optional[List[int]]=None) -> List[int]:
        """
        Given the name of a value, return a list of integers stored under that name.

        Parameters:
            name - Name of attribute
            length - The expected length of the array
            default - The default to return if the value doesn't exist, or isn't a list of integers
                      of the right length.

        Returns:
            A list of integers.
        """
        if default is None:
            default = [0] * length
        if len(default) != length:
            raise Exception('Gave default of wrong length!')

        val = self.get(name)
        if val is None:
            return default
        if type(val) != list:
            return default
        if len(val) != length:
            return default
        for v in val:
            if type(v) != int:
                return default
        return val

    def get_bool_array(self, name: str, length: int, default: Optional[List[bool]]=None) -> List[bool]:
        """
        Given the name of a value, return a list of booleans stored under that name.

        Parameters:
            name - Name of attribute
            length - The expected length of the array
            default - The default to return if the value doesn't exist, or isn't a list of booleans
                      of the right length.

        Returns:
            A list of booleans.
        """
        if default is None:
            default = [False] * length
        if len(default) != length:
            raise Exception('Gave default of wrong length!')

        val = self.get(name)
        if val is None:
            return default
        if type(val) != list:
            return default
        if len(val) != length:
            return default
        for v in val:
            if type(v) != bool:
                return default
        return val

    def get_bytes_array(self, name: str, length: int, default: Optional[List[bytes]]=None) -> List[bytes]:
        """
        Given the name of a value, return a list of bytestrings stored under that name.

        Parameters:
            name - Name of attribute
            length - The expected length of the array
            default - The default to return if the value doesn't exist, or isn't a list of bytestrings
                      of the right length.

        Returns:
            A list of bytestrings.
        """
        if default is None:
            default = [b''] * length
        if len(default) != length:
            raise Exception('Gave default of wrong length!')

        val = self.get(name)
        if val is None:
            return default
        if type(val) != list:
            return default
        if len(val) != length:
            return default
        for v in val:
            if type(v) != bytes:
                return default
        return val

    def get_str_array(self, name: str, length: int, default: Optional[List[str]]=None) -> List[str]:
        """
        Given the name of a value, return a list of strings stored under that name.

        Parameters:
            name - Name of attribute
            length - The expected length of the array
            default - The default to return if the value doesn't exist, or isn't a list of strings
                      of the right length.

        Returns:
            A list of strings.
        """
        if default is None:
            default = [''] * length
        if len(default) != length:
            raise Exception('Gave default of wrong length!')

        val = self.get(name)
        if val is None:
            return default
        if type(val) != list:
            return default
        if len(val) != length:
            return default
        for v in val:
            if type(v) != str:
                return default
        return val

    def get_dict(self, name: str, default: Optional[Dict[Any, Any]]=None) -> 'ValidatedDict':
        """
        Given the name of a value, return a dictionary stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't a dictionary.

        Returns:
            A dictionary, wrapped with this helper class so the same helper methods may be called.
        """
        if default is None:
            default = {}
        validateddefault = ValidatedDict(default)

        val = self.get(name)
        if val is None:
            return validateddefault
        if not isinstance(val, dict):
            return validateddefault
        return ValidatedDict(val)

    def replace_int(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually an integer.
        """
        if val is None:
            return
        if type(val) != int:
            return
        self[name] = val

    def replace_float(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a float
        """
        if val is None:
            return
        if type(val) != float:
            return
        self[name] = val

    def replace_bool(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a boolean.
        """
        if val is None:
            return
        if type(val) != bool:
            return
        self[name] = val

    def replace_str(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a string.
        """
        if val is None:
            return
        if type(val) != str:
            return
        self[name] = val

    def replace_bytes(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a bytestring.
        """
        if val is None:
            return
        if type(val) != bytes:
            return
        self[name] = val

    def replace_int_array(self, name: str, length: int, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            length - Expected length of the list
            val - The value to store, if it is actually a list of integers containing length elements.
        """
        if val is None:
            return
        if type(val) != list:
            return
        if len(val) != length:
            return
        for v in val:
            if type(v) != int:
                return
        self[name] = val

    def replace_bool_array(self, name: str, length: int, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            length - Expected length of the list
            val - The value to store, if it is actually a list of booleans containing length elements.
        """
        if val is None:
            return
        if type(val) != list:
            return
        if len(val) != length:
            return
        for v in val:
            if type(v) != bool:
                return
        self[name] = val

    def replace_bytes_array(self, name: str, length: int, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            length - Expected length of the list
            val - The value to store, if it is actually a list of bytestrings containing length elements.
        """
        if val is None:
            return
        if type(val) != list:
            return
        if len(val) != length:
            return
        for v in val:
            if type(v) != bytes:
                return
        self[name] = val

    def replace_str_array(self, name: str, length: int, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            length - Expected length of the list
            val - The value to store, if it is actually a list of strings containing length elements.
        """
        if val is None:
            return
        if type(val) != list:
            return
        if len(val) != length:
            return
        for v in val:
            if type(v) != str:
                return
        self[name] = val

    def replace_dict(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a dictionary.
        """
        if val is None:
            return
        if not isinstance(val, dict):
            return
        self[name] = val

    def increment_int(self, name: str) -> None:
        """
        Given the name of a value, increment the value by 1.

        If the value doesn't exist or isn't an integer, converts it to an integer
        and sets it to 1 (as if it was 0 before). If it is an integer, increments
        it by 1.

        Parameters:
            name - Name of attribute
        """
        if name not in self:
            self[name] = 1
        elif type(self[name]) != int:
            self[name] = 1
        else:
            self[name] = self[name] + 1
