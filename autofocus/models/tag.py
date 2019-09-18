import json

from datetime import datetime
from ..config import get_logger
from .base import AutoFocusObject
from .base import NotLoaded
from ..factories.tag import TagFactory
from ..factories.tag import TagGroupFactory


class TagDefinition(AutoFocusObject):
    def __init__(self, **kwargs):

        #: int: count of search results
        self.count = kwargs["count"]

        last_hit = kwargs.get("lasthit")
        if last_hit:
            last_hit = datetime.strptime(last_hit, '%Y-%m-%d %H:%M:%S')

        #: Optional[datetime]: the last time there was activity witnessed for the tag search
        self.last_hit = last_hit

        #: str: search name
        self.search_name = kwargs["search_name"]

        #: int: tag definition search status id
        self.tag_definition_status_id = kwargs["tag_definition_search_status_id"]

        #: str: tag definition search status
        self.tag_definition_search_status = kwargs["tag_definition_search_status"]

        #: str: ui search definition
        self.ui_search_definition = kwargs["ui_search_definition"]

    def __str__(self):
        return self.ui_search_definition


class TagReference(AutoFocusObject):

    def __init__(self, **kwargs):

        #: datetime: the time the reference was created
        created = kwargs.get("created")
        if created:
            created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S')

        #: str: source for the reference
        self.source = kwargs.get("source", "").encode('utf8')

        #: str: title of the reference
        self.title = kwargs.get("title", "").encode('utf8')

        #: str: url for the reference
        self.url = kwargs.get("url", "").encode('utf8')

    def __str__(self):
        return self.url


class Tag(AutoFocusObject):
    """
    Notes:
        The Tag should be treated as read-only object matching data found in the AutoFocus REST API. It should NOT
        be instantiated directly. Instead, call the various class method factories to get instance(s) of Tag. See:
        * autofocus.Tag.list
        * autofocus.Tag.get
    """

    _factory = TagFactory()

    def __init__(self, **kwargs):
        #: str: The shorthand name for a tag
        self.name = kwargs["tag_name"]

        #: str: The (Unique) name for a tag, used in searches & URLs
        self.public_name = kwargs["public_tag_name"]

        #: int: the number of samples matching the tag
        self.count = kwargs["count"]

        last_hit = kwargs.get('lasthit')
        if last_hit:
            try:
                last_hit = datetime.strptime(last_hit, '%Y-%m-%d %H:%M:%S')
            except Exception:
                get_logger().warning("Couldn't parse last hit time on tag %s", self.public_name)
                last_hit = None

        #: Optional[datetime]: the last time there was activity witnessed for the tag
        self.last_hit = last_hit

        created = kwargs.get('created_at')
        if created:
            try:
                created = datetime.strptime(created, '%Y-%m-%d %H:%M:%S')
            except Exception:
                get_logger().warning("Couldn't parse created time on tag %s", self.public_name)
                created = None

        #: Optional[datetime]: the datetime the tag was created
        self.created = created

        updated = kwargs.get('updated_at')
        if updated:
            try:
                updated = datetime.strptime(updated, '%Y-%m-%d %H:%M:%S')
            except Exception:
                get_logger().warning("Couldn't parse updated time on tag %s", self.public_name)
                updated = None

        #: Optional[datetime]: the datetime the tag was updated
        self.updated = updated

        #: Optional[str]: the owner of the tag
        self.owner = kwargs.get("owner")

        #: Optional[str]: the authors description of the tag
        self.description = kwargs.get("description", "")

        #: str: The definition status for the tag
        self.status = kwargs["tag_definition_status"]

        #: int: The definition status id for the tag
        self.status_id = kwargs["tag_definition_status_id"]

        #: str: The definition scope for the tag
        self.scope = kwargs["tag_definition_scope"]

        #: int: The definition scoe id for the tag
        self.scope_id = kwargs["tag_definition_scope_id"]

        #: List[TagDefinition]: tag searches
        self.tag_definitions = NotLoaded()

        # Private _tags
        self._tag_definitions = kwargs.get('tag_searches', [])

        #: Optional[str]: The class for the tag. Need to break convention for reserved words in python
        self.tag_class = kwargs.get("tag_class")

        #: Optional[int]: The class id for the tag. Need to break convention for reserved words in python
        self.tag_class_id = kwargs.get("tag_class_id")

        #: Optiona[str]: The name of the customer who wrote the tag. Will be None if not recorded or you
        #                don't have permission to view it
        self.customer_name = kwargs.get("customer_name")

        #: int: up votes for the tag
        self.up_votes = kwargs.get("up_votes", 0)
        if self.up_votes is None:
            self.up_votes = 0

        #: int: Down votes for the tag
        self.down_votes = kwargs.get("down_votes", 0)
        if self.down_votes is None:
            self.down_votes = 0

        #: list[str]: related tag names
        self.related_tag_names = kwargs.get("related_tag_names", NotLoaded())

        #: List[str]: Comments for the given tag
        self.comments = kwargs.get("comments", NotLoaded())
        #: List[str]: a list of references for the tag
        self.references = NotLoaded()

        #: Priveate _references
        self._references = kwargs.get("refs", NotLoaded())

        if type(self._references) in (str, str):
            self.references = []
            if not self._references == "null":
                try:
                    ref_data = json.loads(self._references)
                    for v in ref_data:
                        self.references.append(TagReference(**v))
                except Exception:
                    get_logger().debug("Unable to load tag reference for %s: %s ", self.public_name, self._references)

        #: List[TagGroup]: Tag groups for the given tag
        self._groups = kwargs.get("tag_groups", NotLoaded())

        if type(self._groups) is not NotLoaded:
            self.groups = []
            try:
                for v in self._groups:
                    self.groups.append(TagGroup(**v))
            except Exception:
                get_logger().debug("Unable to load tag groups for %s: %s ", self.public_name, self._groups)

        #: dict: a dictionary with comments in it? Don't we have comments above?
        #: Although we do have comments above, the review comments are a special
        #: class of comment which is treated differently by AF
        self.review = kwargs.get("review", NotLoaded())
        #
        # #: int: The support id for the tag
        # self.support_id = kwargs.get("support_id", NotLoaded())

    def __getattribute__(self, attr):

        value = object.__getattribute__(self, attr)

        # Not offered in the list controller, have to call get to lazy load:
        if attr in ('comments', 'references', 'review', 'support_id',
                    'related_tag_names', 'tag_definitions', 'references') and \
                type(value) is NotLoaded:

            public_name = object.__getattribute__(self, "public_name")
            _factory = object.__getattribute__(self, "_factory")
            new_tag = _factory.get(public_name, use_cache=False)

            # Reloading the data via the get method
            self = new_tag
            value = object.__getattribute__(self, attr)

            # Load tag searches if needed
            if attr == "tag_definitions" and type(value) is NotLoaded:
                value = []
                for tag_definition in object.__getattribute__(self, "_tag_definitions"):
                    value.append(TagDefinition(**tag_definition))
                object.__setattr__(self, 'tag_definitions', value)

            # Current data models are inconsistent, need to throw a warning about defaulting to a false value here
            if type(value) is NotLoaded:
                if attr in ("related_tag_names", "tag_definitions", "references"):
                    value = []
                else:
                    value = None
                get_logger().warning("Unable to lazy load tag attribute, defaulting to a false value! "
                                     "tag:%s attribute:%s\n", public_name, attr)

        return value

    @classmethod
    def search(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.tag.TagFactory.search
        """
        return cls._factory.search(*args, **kwargs)

    @classmethod
    def list(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.tag.TagFactory.list
        """
        return cls._factory.list(*args, **kwargs)

    @classmethod
    def get(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.tag.TagFactory.get
        """
        return cls._factory.get(*args, **kwargs)


class TagGroup(AutoFocusObject):

    _factory = TagGroupFactory()

    def __init__(self, **kwargs):

        #: str: The name of the tag group
        self.name = kwargs.get("tag_group_name")

        #: str: The description of the tag group
        self.description = kwargs.get("description")

        self.tags = NotLoaded()

    @classmethod
    def get(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.tag.TagGroupFactory.get
        """
        return cls._factory.get(*args, **kwargs)

    def __iter__(self):
        return iter(self.tags)

    def __getattribute__(self, attr):

        value = object.__getattribute__(self, attr)

        # Not offered in the list controller, have to call get to lazy load:
        if type(value) is NotLoaded:

            new_tag_group = TagGroup._factory.get(self.name)

            # Reloading the data via the get method
            self = new_tag_group
            value = object.__getattribute__(self, attr)

        return value
