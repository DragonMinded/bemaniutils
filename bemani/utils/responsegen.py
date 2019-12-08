import argparse
import sys
from typing import Dict, List, Optional

from bemani.protocol import EAmuseProtocol, Node


def generate_node_name(node: Node, used_names: Dict[str, Node]) -> str:
    potential_name = node.name
    if potential_name not in used_names:
        used_names[potential_name] = node
        return potential_name

    loop = 1
    while '{}_{}'.format(potential_name, loop) in used_names:
        loop = loop + 1

    potential_name = '{}_{}'.format(potential_name, loop)
    used_names[potential_name] = node
    return potential_name


def generate_node_create(node: Node) -> str:
    dtype = node.data_type
    if dtype == 'str':
        method = 'string'
    elif dtype == 'bin':
        method = 'binary'
    elif dtype == 'ip4':
        method = 'ipv4'
    elif dtype == '4u8':
        method = 'fouru8'
    else:
        method = dtype
    if node.is_array:
        method = '{}_array'.format(method)

    if dtype != 'void':
        # Format the type for display
        if dtype == 'str':
            value = ', \'{}\''.format(node.value)
        elif dtype == 'ip4':
            value = ', \'{}.{}.{}.{}\''.format(
                node.value[0],
                node.value[1],
                node.value[2],
                node.value[3],
            )
        else:
            value = ', {}'.format(node.value)
    else:
        value = ''

    return 'Node.{}(\'{}\'{})'.format(
        method,
        node.name,
        value
    )


def generate_node_link(node_name: str, used_names: Dict[str, Node], parent: Node) -> str:
    # Find the node that parents this, link to it
    found_parent = None
    for parent_name in used_names:
        if used_names[parent_name] is parent:
            found_parent = parent_name
            break

    if found_parent is None:
        raise Exception('Failed to find parent name for {}'.format(parent))

    return '{}.add_child({})'.format(
        found_parent,
        node_name,
    )


def generate_lines(node: Node, used_names: Dict[str, Node], parent: Optional[Node]=None) -> List[str]:
    # First, generate node itself
    create = generate_node_create(node)
    if not node.children and not node.attributes and parent:
        # Just directly hook this up to parent
        return [generate_node_link(create, used_names, parent)]

    # Print the node generate itself
    out = []
    node_name = generate_node_name(node, used_names)
    out.append('{} = {}'.format(node_name, create))

    # Now, generate add to parent if exists
    if parent is not None:
        out.append(generate_node_link(node_name, used_names, parent))

    # Now generate node attributes
    for attr in node.attributes:
        out.append('{}.set_attribute(\'{}\', \'{}\')'.format(
            node_name,
            attr,
            node.attributes[attr],
        ))

    # Now, do the same for all children
    for child in node.children:
        out.extend(generate_lines(child, used_names, node))

    return out


def generate_code(infile: str, outfile: str, encoding: str) -> None:
    if infile == '-':
        # Load from stdin
        packet = sys.stdin.buffer.read()
    else:
        with open(infile, mode="rb") as infp:
            packet = infp.read()
            infp.close

    # Add an XML special node to force encoding (will be overwritten if there
    # is one in the packet).
    packet = b''.join([
        '<?xml encoding="{}"?>'.format(encoding).encode(encoding),
        packet,
    ])

    # Attempt to decode it
    proto = EAmuseProtocol()
    req = proto.decode(
        None,
        None,
        packet,
    )

    if req is None:
        # Can't decode, exit
        raise Exception("Unable to decode packet!")

    # Walk through, outputting each node and attaching it to its parent
    code = '\n'.join(generate_lines(req, {}))

    if outfile == '-':
        print(code)
    else:
        with open(outfile, mode="a") as outfp:
            outfp.write(code)
            outfp.close


def main() -> None:
    parser = argparse.ArgumentParser(description="A utility to generate code that will generate a packet.")
    parser.add_argument("-i", "--infile", help="File containing an XML or binary node structure. Use - for stdin.", type=str, default=None, required=True)
    parser.add_argument("-o", "--outfile", help="File to write python code to. Use - for stdout.", type=str, default=None, required=True)
    parser.add_argument("-e", "--encoding", help="Encoding for the packet, defaults to UTF-8.", type=str, default='utf-8')
    args = parser.parse_args()

    generate_code(args.infile, args.outfile, args.encoding)


if __name__ == '__main__':
    main()
