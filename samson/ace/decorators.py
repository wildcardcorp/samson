from samson.utilities.runtime import RUNTIME

def has_exploit(attack):
    def real_decorator(cls):
        RUNTIME.register_exploit_mapping(cls, attack)
        return cls
    return real_decorator


def creates_constraint(primitive):
    def real_decorator(cls):
        RUNTIME.constraints[cls] = primitive
        return cls
    return real_decorator


def define_exploit(consequence, requirements):
    def real_decorator(cls):
        RUNTIME.register_exploit(cls, consequence, requirements)
        return cls
    return real_decorator
