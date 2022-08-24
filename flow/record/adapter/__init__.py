__path__ = __import__("pkgutil").extend_path(__path__, __name__)  # make this namespace extensible from other packages
import abc


def with_metaclass(meta, *bases):
    """Create a base class with a metaclass. Python 2 and 3 compatible."""
    # This requires a bit of explanation: the basic idea is to make a dummy
    # metaclass for one level of class instantiation that replaces itself with
    # the actual metaclass.
    class metaclass(type):
        def __new__(cls, name, this_bases, d):
            return meta(name, bases, d)

        @classmethod
        def __prepare__(cls, name, this_bases):
            return meta.__prepare__(name, bases)

    return type.__new__(metaclass, "temporary_class", (), {})


class AbstractWriter(with_metaclass(abc.ABCMeta, object)):
    @abc.abstractmethod
    def write(self, rec):
        """Write a record."""
        raise NotImplementedError

    @abc.abstractmethod
    def flush(self):
        """Flush any buffered writes."""
        raise NotImplementedError

    @abc.abstractmethod
    def close(self):
        """Close the Writer, no more writes will be possible."""
        raise NotImplementedError

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.flush()
        self.close()


class AbstractReader(with_metaclass(abc.ABCMeta, object)):
    @abc.abstractmethod
    def __iter__(self):
        """Return a record iterator."""
        raise NotImplementedError

    def close(self):
        """Close the Reader, can be overriden to properly free resources."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
