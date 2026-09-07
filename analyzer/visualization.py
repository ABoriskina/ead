from html import escape
from pathlib import Path

import networkx as nx
from pyvis.network import Network

NODE_COLORS = {
    "process": "#4C78A8",
    "file": "#FF751F",
    "network": "#56B7E4",
}

FULLSCREEN_STYLE = """
<style>
html, body {
  width: 100%;
  height: 100%;
  margin: 0;
  overflow: hidden;
}
.card {
  width: 100% !important;
  height: 100% !important;
  border: 0 !important;
}
#mynetwork {
  position: fixed !important;
  inset: 0;
  width: 100vw !important;
  height: 100vh !important;
  padding: 0 !important;
  border: 0 !important;
  float: none !important;
}
#loadingBar {
  position: fixed !important;
  inset: 0;
  width: 100vw !important;
  height: 100vh !important;
}
</style>
"""

FIT_GRAPH_SCRIPT = """
              drawGraph();
              network.once("stabilizationIterationsDone", function () {
                  network.fit({animation: false});
              });
              window.setTimeout(function () {
                  network.fit({animation: false});
              }, 250);
              window.addEventListener("resize", function () {
                  network.fit({animation: false});
              });
"""


def visualize_graph(
    graph: nx.MultiDiGraph,
    output_path: str = "event-graph.html",
):
    network = Network(
        height="100vh",
        width="100vw",
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
            label = (
                f"{attributes.get('comm')} ({attributes.get('pid')})"
                if entity_type == "process"
                else attributes.get("pathname")
                or attributes.get("address")
                or str(node_id)
            ),
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

    html = network.generate_html()
    html = html.replace("</head>", f"{FULLSCREEN_STYLE}</head>", 1)
    html = html.replace("              drawGraph();", FIT_GRAPH_SCRIPT, 1)
    Path(output_path).write_text(html, encoding="utf-8")


def get_node_shape(entity_type: str) -> str:
    return {
        "process": "dot",
        "file": "box",
        "network": "diamond",
    }.get(entity_type, "ellipse")
