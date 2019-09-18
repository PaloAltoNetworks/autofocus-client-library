import decimal
import json
from datetime import datetime
from datetime import date
from ..config import get_logger


class NotLoaded:
    """
    NotLoaded is a class used internally by various classes in this module for handling when an attribute needs to be
    lazy loaded. This class is not meant for general use.
    """
    pass


class AutoFocusObject:

    def __init__(self, **kwargs):
        for k, v in list(kwargs.items()):
            setattr(self, k, v)

    def __str__(self):
        return json.dumps(self.serialize())

    def serialize(self, depth=1, include_all=True):
        """ Converts object to a dictionary representation. Depending on combination
            of depth and include_all parameters, performance on serialization may suffer,
            especially if trying to serialize many objects. Using a lower depth and/or setting
            include_all to False will reduce the number of API calls made during serialization

            Args:
                depth: how many nested objects to include in dictionary
                include_all: whether or not to include lazy loaded attributes.

            Returns:
                dictionary containing attributes and values
        """
        serialized = {}

        # stop if we hit specified depth
        if depth == 0:
            return None

        obj_attrs = {}

        # decide if we should include or not include attributes based on lazy loading
        for k in self.__dict__.keys():
            if include_all:
                # lazy load everything and include it
                obj_attrs[k] = getattr(self, k)
            else:
                raw_value = super(AutoFocusObject, self).__getattribute__(k)
                # don't include lazy loaded attributes or private variables
                if not (isinstance(raw_value, NotLoaded) or k.startswith("_")):
                    obj_attrs[k] = raw_value

        # serialize
        for (k, v) in obj_attrs.items():

            if isinstance(v, list):
                serialized_array = []
                for item in v:
                    if isinstance(item, AutoFocusObject):
                        if depth > 1:
                            serialized_array.append(item.serialize(depth=depth - 1))
                    elif isinstance(item, (datetime, date)):
                        serialized_array.append(item.isoformat())
                    elif isinstance(item, decimal.Decimal):
                        serialized_array.append(f"{item:.1f}")
                    elif isinstance(item, (str, int, dict)):
                        serialized_array.append(item)

                # Only add if we actually have data in the list, this will be empty in the case that all of the members
                # are AutofocusObjects and we are past the recursion depths (Think AFSample.tags)
                if serialized_array:
                    serialized[k] = serialized_array
                elif not v:  # If v just didn't have anything it, give it an emtpy array
                    serialized[k] = []

            elif isinstance(v, AutoFocusObject):
                # only encode hard coded relations (via __serializable_relations__)
                # to prevent huge data returns and infinite loops
                if depth > 1:
                    serialized[k] = v.serialize(depth=depth - 1)
            elif isinstance(v, NotLoaded):
                # this really shouldn't be happening
                get_logger().warning("Failed to load '%s:%s' while serializing - setting to None", k, v)
                serialized[k] = None
            else:
                if isinstance(v, (datetime, date)):
                    serialized[k] = v.isoformat()
                elif isinstance(v, decimal.Decimal):
                    serialized[k] = f"{v:.1f}"
                else:
                    serialized[k] = v

        return serialized
