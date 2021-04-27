import yaml
import inspect
import scapy.all as scapy_all
from typing import Callable, Dict, Any, List, Set, Optional
from copy import deepcopy, copy
import logging

log = logging.getLogger(__name__)


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
    global gzilla_var
    # TODO: Are there any aliases that depend on the function called?
    aliases = {"packets": "x", "interface": "iface"}

    for key, value in aliases.items():
        while key in args:
            # packets is an alias for 'x' in 'send' and 'sendp'
            args[value] = args.pop(key)

    log.debug("in parse_args with {}".format(args))

    for key, value in args.items():
        log.debug("parsing {} ({}), {} ({})".format(key, type(key), value, type(value)))
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
        if isinstance(value, str) and value == "GZILLA_VAR" and gzilla_var is not None:
            args[key] = gzilla_var

        elif isinstance(value, dict):  # lambda call each key in function
            if key == "prn":
                # callback function on each packet
                methodObject = args[key]  # Error Handling?

                def prn(packet: Any) -> None:
                    log.debug(dir(packet))
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
            if key == "loop":
                # callback function on each packet
                count = args[key]["count"]  # Error Handling?
                methodObject = args[key]["method"]  # Error Handling?
                if "variable" in args[key]:
                    gzilla_var_eval = args[key]["variable"]
                    gzilla_var = eval(gzilla_var_eval[7:])

                def loop() -> None:
                    for i in range(count):
                        parse_and_run(deepcopy(methodObject))

                args[key] = loop

            elif key == "qd":  # DNSQR
                args[key] = scapy_all.DNSQR(**parse_args(value, packet_arg=packet_arg))
            elif key in ["an", "ns", "ar"]:  # DNSQR
                args[key] = scapy_all.DNSRR(**parse_args(value, packet_arg=packet_arg))
            else:
                raise Exception(
                    f"Invalid Function Call Argument {key}. TODO: Narrow Exception Type"
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
                        log.debug(match)
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

                log.info(f"Built packets: {packets}")
                args["x"] = packets
            else:
                raise Exception("Invalid List Element in Yaml.")

        else:
            pass  # Leave other arguments unmodified

    log.debug(f"args: {args}")

    return args


def execute_yaml(yamlfile: str) -> bool:
    """
    It wouldn't be crazy hard to compile the yaml to python too...
    """
    try:
        with open(yamlfile, "r") as f:
            yaml_code = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        log.error("Error in configuration file:", exc)

    # Lil hack for xxxx.example.edu
    global gzilla_var
    gzilla_var = None

    return parse_and_run(yaml_code)


def parse_and_run(yaml_code: Dict) -> bool:
    log.debug(f"parse_and_run: {yaml_code}")
    # {'sniff': {'interface': 'eth0', 'filter': 'tcp and portrange 50-100', 'count': 10, 'quiet': False}}

    # {'sniff': {'interface': 'eth0', 'filter': 'icmp and icmp[icmptype] == icmp-echo', 'count': 10,
    # 'prn': {'sendp': {'packets': [{'Ether': {'src': '01:02:03:04:05', 'IP': {'dst':
    # 'python:packet.src', 'src': 'python:packet.dst', 'ICMP': {'type': 0, 'code': 0}}}}],
    # 'iface': 'eth0'}}}}

    # TODO: Test everything before calling it?
    # TODO: Handle aliases
    # TODO: Nice error messages
    try:
        for key in yaml_code.keys():
            loop = False
            try:
                method = getScapyMethod(key)  # Error Handling?
            except AttributeError as e:
                if key == "loop":
                    log.info(f"Loop detected with key: {key}, {yaml_code}")
                    method = None
                    loop = True
                else:
                    log.error(f"AttributeError: {e}")

            if loop:
                args = parse_args({"loop": yaml_code[key]})
                method = args["loop"]
                loop = True
            else:
                args = parse_args(yaml_code[key])

            if not loop:
                log.info(f"{key} is callable with {args}.")
                log.info(f"Calling {key}(**{args})")
                method(**args)
            else:
                method()

        return True
    except Exception as e:
        log.warning("Unable to execute yaml:")
        log.warning(e)
        return False
