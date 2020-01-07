from typing import Optional


class ID:

    @staticmethod
    def format_extid(extid: int) -> str:
        """
        Take an ExtID as an integer, format it as a string.

        If we had the ExtID 12345678, this would format as '1234-5678'

        Parameters:
            extid - The ID as an integer

        Returns:
            A string suitable for display to the user.
        """
        extid_str = str(extid)
        while len(extid_str) < 8:
            extid_str = '0' + extid_str
        return f'{extid_str[0:4]}-{extid_str[4:8]}'

    @staticmethod
    def parse_extid(extid: str) -> Optional[int]:
        """
        Take an ExtID as a string, and return the integer.

        If we had the ExtID '1234-5678', this would return 12345678.

        Parameters:
            extid - The string ID as shown to a suer

        Returns:
            An integer extid suitable for looking up in a DB.
        """
        try:
            if len(extid) == 9 and extid[4:5] == '-':
                return int(extid[0:4] + extid[5:9])
        except ValueError:
            pass
        return None

    @staticmethod
    def format_machine_id(machine_id: int) -> str:
        """
        Take a machine ID as an integer, format it as a string.
        """
        return f'US-{machine_id}'

    @staticmethod
    def parse_machine_id(machine_id: str) -> Optional[int]:
        """
        Take a formatted machine ID as a string, returning an int.
        """
        try:
            if machine_id[:3] == 'US-':
                return int(machine_id[3:])
        except ValueError:
            pass
        return None
