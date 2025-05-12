import argparse
import ipaddress
from xml.etree.ElementTree import Element, SubElement, ElementTree

asa_objects = {}
asa_object_groups = {}

def to_cidr(ip_str, mask_str):
    try:
        network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        return str(network.network_address) + '/' + str(network.prefixlen)
    except ValueError:
        return ip_str

def parse_object_definitions(lines):
    current_name = None
    for line in lines:
        line = line.strip()
        if line.startswith("object network"):
            current_name = line.split()[-1]
        elif line.startswith("host") and current_name:
            ip = line.split()[1]
            asa_objects[current_name] = ip
        elif line.count('.') == 3 and current_name:
            parts = line.split()
            if len(parts) == 2:
                ip, mask = parts
                asa_objects[current_name] = to_cidr(ip, mask)

def parse_object_group_definitions(lines):
    current_group = None
    for line in lines:
        line = line.strip()
        if line.startswith("object-group network"):
            current_group = line.split()[-1]
            asa_object_groups[current_group] = []
        elif line.startswith("network-object") and current_group:
            parts = line.split()
            if parts[1] == 'host':
                asa_object_groups[current_group].append(parts[2])
            elif len(parts) == 3:
                ip, mask = parts[1], parts[2]
                asa_object_groups[current_group].append(to_cidr(ip, mask))

def convert_objects_and_groups_to_xml(parent):
    shared = SubElement(parent, "shared")
    address = SubElement(shared, "address")
    address_group = SubElement(shared, "address-group")

    for name, ip in asa_objects.items():
        entry = SubElement(address, "entry", {"name": name})
        SubElement(entry, "ip-netmask").text = ip

    for group_name, members in asa_object_groups.items():
        static_entry = SubElement(address_group, "entry", {"name": group_name})
        static = SubElement(static_entry, "static")
        for i, ip in enumerate(members, start=1):
            obj_name = f"{group_name}_{i}"
            entry = SubElement(address, "entry", {"name": obj_name})
            SubElement(entry, "ip-netmask").text = ip
            SubElement(static, "member").text = obj_name

def parse_asa_rule(line):
    parts = line.strip().split()

    if parts[0] == "access-list" and "to" in parts:
        to_index = parts.index("to")
        from_zone = parts[1].upper()
        to_zone = parts[to_index + 1].upper()
        acl_name = f"{from_zone}_TO_{to_zone}"
        rule_parts = parts[to_index + 2:]
    else:
        from_zone = 'UNKNOWN'
        to_zone = 'UNKNOWN'
        acl_name = parts[1]
        rule_parts = parts[2:]

    if rule_parts[0] == 'extended':
        rule_parts = rule_parts[1:]

    action = rule_parts[0]
    protocol = rule_parts[1]
    index = 2

    if rule_parts[index] == 'host':
        source = rule_parts[index + 1]
        index += 2
    elif rule_parts[index] == 'object':
        obj_name = rule_parts[index + 1]
        source = asa_objects.get(obj_name, obj_name)
        index += 2
    elif rule_parts[index] == 'object-group':
        group_name = rule_parts[index + 1]
        source = group_name
        index += 2
    elif rule_parts[index].count('.') == 3 and rule_parts[index + 1].count('.') == 3:
        source = to_cidr(rule_parts[index], rule_parts[index + 1])
        index += 2
    else:
        source = rule_parts[index]
        index += 1

    if rule_parts[index] == 'host':
        destination = rule_parts[index + 1]
        index += 2
    elif rule_parts[index] == 'object':
        obj_name = rule_parts[index + 1]
        destination = asa_objects.get(obj_name, obj_name)
        index += 2
    elif rule_parts[index] == 'object-group':
        group_name = rule_parts[index + 1]
        destination = group_name
        index += 2
    elif rule_parts[index].count('.') == 3 and rule_parts[index + 1].count('.') == 3:
        destination = to_cidr(rule_parts[index], rule_parts[index + 1])
        index += 2
    else:
        destination = rule_parts[index]
        index += 1

    port = 'any'
    if index < len(rule_parts):
        if rule_parts[index] == 'eq' and index + 1 < len(rule_parts):
            port = rule_parts[index + 1]

    return {
        'acl_name': acl_name,
        'from_zone': from_zone,
        'to_zone': to_zone,
        'action': action,
        'protocol': protocol,
        'source': source,
        'destination': destination,
        'port': port
    }

def convert_to_palo(rule, index, include_tags=True, tag_name="from-asa"):
    palo_action = 'allow' if rule['action'].lower() == 'permit' else 'deny'
    service = f"{rule['protocol']}-{rule['port']}" if rule['protocol'] in ['tcp', 'udp'] and rule['port'] != 'any' else 'any'
    rule_name = f"{rule['acl_name']}_{index}"

    def format_value(val):
        if isinstance(val, list):
            return f"[ {' '.join(val)} ]"
        return val

    src = format_value(rule['source'])
    dst = format_value(rule['destination'])

    palo_rule = [
        f"set rulebase security rules {rule_name} from {rule['from_zone']}",
        f"set rulebase security rules {rule_name} to {rule['to_zone']}",
        f"set rulebase security rules {rule_name} source {src}",
        f"set rulebase security rules {rule_name} destination {dst}",
        f"set rulebase security rules {rule_name} service {service}",
        f"set rulebase security rules {rule_name} action {palo_action}",
        f"set rulebase security rules {rule_name} source-user any",
        f"set rulebase security rules {rule_name} disabled no",
        f"set rulebase security rules {rule_name} log-start no",
        f"set rulebase security rules {rule_name} log-end yes"
    ]

    if include_tags:
        palo_rule.append(f'set rulebase security rules {rule_name} description "Converted from ASA rule: {rule_name}"')
        palo_rule.append(f"set rulebase security rules {rule_name} tag {tag_name}")

    return palo_rule

def convert_objects_and_groups():
    cmds = []

    # Generate address object commands
    for name, ip in asa_objects.items():
        cmds.append(f'set address "{name}" ip-netmask {ip}')

    # Generate address-group commands
    for group_name, members in asa_object_groups.items():
        member_names = []
        for idx, member_ip in enumerate(members, start=1):
            obj_name = f"{group_name}_{idx}"
            cmds.append(f'set address "{obj_name}" ip-netmask {member_ip}')
            member_names.append(f'"{obj_name}"')
        member_str = "[ " + " ".join(member_names) + " ]"
        cmds.append(f'set address-group {group_name} static {member_str}')

    return cmds

def convert_asa_to_palo(input_file, output_file, include_tags=True, tag_name="from-asa"):
    with open(input_file, 'r') as f:
        lines = f.readlines()

    parse_object_definitions(lines)
    parse_object_group_definitions(lines)
    access_rules = [line for line in lines if line.startswith("access-list")]

    with open(output_file, 'w') as out:
        obj_cmds = convert_objects_and_groups()
        out.write('\n'.join(obj_cmds) + '\n\n')

        for idx, line in enumerate(access_rules, start=1):
            rule = parse_asa_rule(line)
            palo_cmds = convert_to_palo(rule, idx, include_tags=include_tags, tag_name=tag_name)
            out.write('\n'.join(palo_cmds) + '\n\n')

    print(f"Palo Alto config written to: {output_file}")

def export_to_panorama_xml(input_file, output_file, device_group, tag_name="from-asa"):
    with open(input_file, 'r') as f:
        lines = f.readlines()

    parse_object_definitions(lines)
    parse_object_group_definitions(lines)
    access_rules = [line for line in lines if line.startswith("access-list")]

    config = Element("config")
    devices = SubElement(config, "devices")
    entry_dev = SubElement(devices, "entry", {"name": "localhost.localdomain"})

    # Add shared address/address-group
    convert_objects_and_groups_to_xml(entry_dev)

    dg = SubElement(entry_dev, "device-group")
    dg_entry = SubElement(dg, "entry", {"name": device_group})
    pre_rulebase = SubElement(dg_entry, "pre-rulebase")
    security = SubElement(pre_rulebase, "security")
    rules = SubElement(security, "rules")

    for idx, line in enumerate(access_rules, start=1):
        rule = parse_asa_rule(line)
        rule_name = f"{rule['acl_name']}_{idx}"
        rule_elem = SubElement(rules, "entry", {"name": rule_name})

        def append_members(elem_name, value):
            e = SubElement(rule_elem, elem_name)
            if isinstance(value, list):
                for v in value:
                    SubElement(e, "member").text = v
            else:
                SubElement(e, "member").text = value

        append_members("from", rule['from_zone'])
        append_members("to", rule['to_zone'])
        append_members("source", rule['source'])
        append_members("destination", rule['destination'])

        if rule['protocol'] in ['tcp', 'udp'] and rule['port'] != 'any':
            service = f"{rule['protocol']}-{rule['port']}"
        else:
            service = "any"
        append_members("service", service)

        SubElement(rule_elem, "action").text = 'allow' if rule['action'].lower() == 'permit' else 'deny'
        append_members("source-user", "any")
        SubElement(rule_elem, "log-end").text = "yes"
        SubElement(rule_elem, "description").text = f"Converted from ASA rule: {rule_name}"
        append_members("tag", tag_name)

    tree = ElementTree(config)
    tree.write(output_file, encoding="utf-8", xml_declaration=True)
    print(f"Panorama XML written to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Convert ASA rules to Palo Alto format.')
    parser.add_argument('input_file', help='ASA config input file')
    parser.add_argument('output_file', help='Output file')
    parser.add_argument('--xml', action='store_true', help='Export as XML for Panorama')
    parser.add_argument('--dg', '--device-group', dest='device_group', default='MyDeviceGroup', help='Panorama device group name')
    parser.add_argument('--no-tags', action='store_true', help='Disable adding tags and descriptions to output rules')
    parser.add_argument('--tag-name', default='from-asa', help='Custom tag name to apply to rules')
    args = parser.parse_args()

    if args.xml:
        export_to_panorama_xml(args.input_file, args.output_file, args.device_group, tag_name=args.tag_name)
    else:
        convert_asa_to_palo(args.input_file, args.output_file, include_tags=not args.no_tags, tag_name=args.tag_name)

if __name__ == '__main__':
    main()
