import yaml
import inspect
import scapy.all as scapy_all
from typing import Callable, Dict, Any, List, Set

# https://stackoverflow.com/questions/196960/can-you-list-the-keyword-arguments-a-function-receives
def getRequiredArgs(func: Callable[..., Any]) -> List[str]:
    args, varargs, varkw, defaults = inspect.getargspec(func)
    if defaults:
        args = args[: -len(defaults)]
    return args  # *args and **kwargs are not required, so ignore them.


def missingArgs(func: Callable[..., Any], argdict: Dict[str, Any]) -> Set[str]:
    return set(getRequiredArgs(func)).difference(argdict)


def invalidArgs(func: Callable[..., Any], argdict: Dict[str, Any]) -> Set[str]:
    args, varargs, varkw, defaults = inspect.getargspec(func)
    if varkw:
        return set()  # All accepted
    return set(argdict) - set(args)


def isCallableWithArgs(func: Callable[..., Any], argdict: Dict[str, Any]) -> bool:
    return not missingArgs(func, argdict) and not invalidArgs(func, argdict)


def execute_yaml(yamlfile: str) -> bool:
    """
    It wouldn't be crazy hard to compile the yaml to python too...
    """
    try:
        with open(yamlfile, "r") as f:
            yaml_code = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        print("Error in configuration file:", exc)

    print(yaml_code)
    # {'sniff': {'interface': 'eth0', 'filter': 'tcp and portrange 50-100', 'count': 10, 'quiet': False}}
    # TODO: Do keys keep their order in yaml?
    # TODO: Test everything before calling it.
    # TODO: Parse all args (recursively if needed)
    # TODO: Handle special case methods that don't take keyword args (mainly send and sendp)
    # TODO: Handle aliases
    for key in yaml_code.keys():
        try:
            method = getattr(scapy_all, key)
        except AttributeError as e:
            raise e

        args = yaml_code[key]

        isCallable = isCallableWithArgs(method, args)
        if isCallable:
            print(f"{key} is Callable with {args}.")
            print(f"Calling {key}(**{args})")
            method(**args)
        else:
            return False

    return True


def validate_yaml(yamlfile: str) -> bool:
    """
    It wouldn't be crazy hard to compile the yaml to python too...
    """
    try:
        with open(yamlfile, "r") as f:
            yaml_code = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        print("Error in configuration file:", exc)

    print(yaml_code)
    # {'sniff': {'interface': 'eth0', 'filter': 'tcp and portrange 50-100', 'count': 10, 'quiet': False}}
    # TODO: Do keys keep their order in yaml?
    # TODO: Test everything before calling it.
    # TODO: Parse all args (recursively if needed)
    # TODO: Handle special case methods that don't take keyword args (mainly send and sendp)
    # TODO: Handle aliases
    for key in yaml_code.keys():
        try:
            method = getattr(scapy_all, key)
        except AttributeError as e:
            raise e

        args = yaml_code[key]

        isCallable = isCallableWithArgs(method, args)
        if isCallable:
            print(f"{key} is callable with {args}.")
        else:
            print(f"{key} is not callable with {args}.")
            return False

    return True
