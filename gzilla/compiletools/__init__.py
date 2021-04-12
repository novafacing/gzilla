import yaml
import inspect
import scapy.all as scapy_all
from typing import Callable, Dict, Any, List, Set
from copy import deepcopy

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


def getScapyMethod(method_str: str) -> Any:
    try:
        method = getattr(scapy_all, method_str)
    except AttributeError as e:
        raise e

    return method


def callYamlMethod(method: Callable[..., Any], argdict: Dict[str, Any]) -> Any:
    return method(**parse_args(argdict))


def parse_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    This modifies `args`.
    """

    while "packets" in args:
        # packets is an alias for 'x' in 'send' and 'sendp'
        args["x"] = args.pop("packets")

    print("in parse_args with {}".format(args))

    for key, value in args.items():
        print("parsing {}, {}".format(key, value))
        if isinstance(value, str) and value.startswith("python:"):
            args[key] = eval(value[7:])  # TODO: Is there a better way
        elif isinstance(value, dict):  # lambda call each key in function
            if key == "prn":
                # callback function on each packet
                methodObject = args[key]  # Error Handling?

                def prn(packet: Any) -> None:
                    for key in methodObject.keys():
                        if key == "send":
                            method = getScapyMethod(key)
                            method(x=[packet], **parse_args(methodObject[key]))
                        elif key == "sendp":
                            method = getScapyMethod(key)
                            method(x=[packet], **parse_args(methodObject[key]))
                        else:
                            raise Exception(
                                "Invalid Scapy Function for prn. TODO: Narrow Exception Name"
                            )

                args[key] = prn
            else:
                raise Exception(
                    "Invalid Function Call Argument. TODO: Narrow Exception Type"
                )

            args[key] = lambda *args, **kwargs: getattr(scapy_all, value[key])(
                *args, **kwargs
            )
        elif isinstance(value, list):  # Parse each element in the list
            if key == "x":
                packets = []
                for packetObject in value:
                    packet = None

                    for match in (
                        x for x in ["Ether", "IP", "ICMP"] if x in packetObject
                    ):
                        copiedObject = {
                            k: packetObject[match][k]
                            for k in packetObject[match].keys()
                            if k not in ["Ether", "IP", "ICMP"]
                        }

                        if packet is None:
                            packet = getScapyMethod(match)(**parse_args(copiedObject))
                        else:
                            packet /= getScapyMethod(match)(**parse_args(copiedObject))

                        packetObject = packetObject[match]

                    if packet:
                        packets.append(packet)

                print("Built packets:", packets)
                args["x"] = packets
            else:
                raise Exception("Invalid List Element in Yaml.")

        else:
            pass  # Leave other arguments unmodified

    print("args:", args)

    return args


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

    # {'sniff': {'interface': 'eth0', 'filter': 'icmp and icmp[icmptype] == icmp-echo', 'count': 10,
    # 'prn': {'sendp': {'packets': [{'Ether': {'src': '01:02:03:04:05', 'IP': {'dst':
    # 'python:packet.src', 'src': 'python:packet.dst', 'ICMP': {'type': 0, 'code': 0}}}}],
    # 'iface': 'eth0'}}}}

    # TODO: Test everything before calling it?
    # TODO: Handle aliases
    # TODO: Nice error messages
    # TODO: use logging.log (+ coloredlogs) instead of print statements
    for key in yaml_code.keys():

        method = getScapyMethod(key)  # Error Handling?

        args = parse_args(yaml_code[key])

        # TODO: Try-catch instead of isCallable?
        isCallable = isCallableWithArgs(method, args)
        if isCallable:
            print(f"{key} is callable with {args}.")
            print(f"Calling {key}(**{args})")
            method(**args)
        else:
            print(f"{key} is not callable with {args}.")
            return False

    return True
