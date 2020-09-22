#!/usr/bin/env python3
import re
from stix_shifter_utils.stix_translation.src.utils.transformers import ValueTransformer


class FilterIPv4List(ValueTransformer):
    """A value transformer for filtering-out from a list all values which are not valid IPv4 values"""

    @staticmethod
    def transform(obj):
        if isinstance(obj, list):
            pattern = re.compile(
                r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
            result = []
            for val in obj:
                if pattern.match(str(val)):
                    result.append(val)
            return result
        return obj


class FilterIPv6List(ValueTransformer):
    """A value transformer for filtering-out from a list all values which are not valid IPv6 values"""

    @staticmethod
    def transform(obj):
        if isinstance(obj, list):
            pattern = re.compile(
                r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$')
            result = []
            for val in obj:
                if pattern.match(str(val)):
                    result.append(val)
            return result
        return obj


class UserDomainToAccountType(ValueTransformer):
    @staticmethod
    def transform(obj):
        windows_local_values_set = {'nt authority', 'windows manager'}
        if str(obj).lower() in windows_local_values_set:
            return 'windows-local'
        else:
            return 'windows-domain'


def get_all_transformers():
    return {"FilterIPv4List": FilterIPv4List, "FilterIPv6List": FilterIPv6List,
            "UserDomainToAccountType": UserDomainToAccountType}
