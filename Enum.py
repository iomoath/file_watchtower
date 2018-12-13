class Enum(set):
    """For creating ENUMs"""
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError
