import yaml
import inspect
import scapy.all as scapy_all
from typing import Callable, Dict, Any, List, Set, Optional
from copy import deepcopy, copy

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


def parse_args(
    args: Dict[str, Any], packet_arg: Optional[Any] = None
) -> Dict[str, Any]:
    """
    This modifies `args`.
    """
    # TODO: Are there any aliases that depend on the function called?
    aliases = {"packets": "x", "interface": "iface"}

    for key, value in aliases.items():
        while key in args:
            # packets is an alias for 'x' in 'send' and 'sendp'
            args[value] = args.pop(key)

    # Remove count & method (for loop key)
    if "count" in args.keys():
        args.pop("count")
    if "method" in args.keys():
        args.pop("method")

    print("in parse_args with {}".format(args))

    for key, value in args.items():
        print("parsing {} ({}), {} ({})".format(key, type(key), value, type(value)))
        if isinstance(value, str) and value.startswith("python:"):
            args[key] = eval(value[7:])  # TODO: Is there a better way
        if isinstance(value, str) and value.startswith("packet:"):
            if packet_arg is None:
                raise Exception("Packet doesn't exist.")
            _, x, y = value.split(":")
            if x not in ["Ether", "IP", "ICMP", "UDP", "DNS", "Raw"]:
                raise Exception("Part doesn't exist.")
            # TODO: try-catch
            args[key] = getattr(packet_arg[getScapyMethod(x)], y)

        elif isinstance(value, dict):  # lambda call each key in function
            if key == "prn":
                # callback function on each packet
                methodObject = args[key]  # Error Handling?

                def prn(packet: Any) -> None:
                    print(dir(packet))
                    for key in methodObject.keys():
                        if key == "send":
                            method = getScapyMethod(key)
                            method(
                                **parse_args(
                                    deepcopy(methodObject[key]), packet_arg=packet
                                )
                            )
                        elif key == "sendp":
                            method = getScapyMethod(key)
                            # TODO: Make deepcopy not required - bug elsewhere modifies it
                            method(
                                **parse_args(
                                    deepcopy(methodObject[key]), packet_arg=packet
                                )
                            )
                        else:
                            raise Exception(
                                "Invalid Scapy Function for prn. TODO: Narrow Exception Name"
                            )

                args[key] = prn
            elif key == "qd":  # DNSQR
                args[key] = scapy_all.DNSQR(**parse_args(value, packet_arg=packet_arg))
            elif key in ["an", "ns", "ar"]:  # DNSQR
                args[key] = scapy_all.DNSRR(**parse_args(value, packet_arg=packet_arg))
            else:
                raise Exception(
                    "Invalid Function Call Argument. TODO: Narrow Exception Type"
                )

                # args[key] = lambda *args, **kwargs: getattr(scapy_all, value[key])(
                #    *args, **kwargs
                # )

        elif isinstance(value, list):  # Parse each element in the list
            if key == "x":
                packets = []
                for packetObject in value:
                    packet = None

                    for match in (
                        x
                        for x in ["Ether", "IP", "ICMP", "UDP", "DNS", "Raw"]
                        if x in packetObject
                    ):
                        print(match)
                        copiedObject = {
                            k: packetObject[match][k]
                            for k in packetObject[match].keys()
                            if k not in ["Ether", "IP", "ICMP", "UDP", "DNS", "Raw"]
                        }

                        if packet is None:
                            packet = getScapyMethod(match)(
                                **parse_args(copiedObject, packet_arg=packet_arg)
                            )
                        else:
                            packet /= getScapyMethod(match)(
                                **parse_args(copiedObject, packet_arg=packet_arg)
                            )

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
    loop = False
    for key in yaml_code.keys():
        if key == "loop":
            print("Parsed loop")
            loop = True

        if loop:
            count = yaml_code["loop"]["count"]
            print("Parsed count: {}".format(count))

            method = getScapyMethod(yaml_code["loop"]["method"])
            print("Parsed method")

            # Only parse once
            args = parse_args(yaml_code[key])

            for i in range(count):
                # TODO: make function since it's being reused in else
                # TODO: Try-catch instead of isCallable?
                isCallable = isCallableWithArgs(method, args)
                if isCallable:
                    print(f"{key} is callable with {args}.")
                    print(f"Calling {key}(**{args})")
                    method(**args)
                else:
                    print(f"{key} is not callable with {args}.")
                    return False

        else:
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
