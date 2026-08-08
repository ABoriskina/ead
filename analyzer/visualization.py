from html import escape

import networkx as nx
from pyvis.network import Network

NODE_COLORS = {
    "process": "#4C78A8",
    "file": "#F2CF5B",
    "network": "#E45756",
}


def visualize_graph(
    graph: nx.MultiDiGraph,
    output_path: str = "event-graph.html",
):
    network = Network(
        height="800px",
        width="100%",
        directed=True,
        bgcolor="#1e1e1e",
        font_color="white",
        cdn_resources="in_line",
    )

    for node_id, attributes in graph.nodes(data=True):
        entity_type = attributes.get("entity_type", "unknown")

        title_lines = [
            f"<b>{escape(str(node_id))}</b>",
            f"type: {escape(str(entity_type))}",
        ]

        for name, value in attributes.items():
            title_lines.append(
                f"{escape(str(name))}: {escape(str(value))}"
            )

        network.add_node(
            node_id,
            label=attributes.get("comm")
            or attributes.get("pathname")
            or attributes.get("address")
            or str(node_id),
            title="<br>".join(title_lines),
            color=NODE_COLORS.get(entity_type, "#999999"),
            shape=get_node_shape(entity_type),
        )

    for source, target, key, attributes in graph.edges(
        keys=True,
        data=True,
    ):
        operation = attributes.get("operation", "UNKNOWN")

        title_lines = [
            f"operation: {escape(str(operation))}",
        ]

        for name, value in attributes.items():
            title_lines.append(
                f"{escape(str(name))}: {escape(str(value))}"
            )

        network.add_edge(
            source,
            target,
            label=operation,
            title="<br>".join(title_lines),
            arrows="to",
        )

    network.set_options("""
    {
      "physics": {
        "enabled": true,
        "barnesHut": {
          "gravitationalConstant": -5000,
          "springLength": 180
        }
      },
      "edges": {
        "smooth": {
          "enabled": true,
          "type": "dynamic"
        },
        "font": {
          "color": "#ffffff",
          "size": 11
        }
      },
      "interaction": {
        "hover": true,
        "navigationButtons": true,
        "keyboard": true
      }
    }
    """)

    network.write_html(output_path)


def get_node_shape(entity_type: str) -> str:
    return {
        "process": "dot",
        "file": "box",
        "network": "diamond",
    }.get(entity_type, "ellipse")
