import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';

export default function NetworkMap({ graphData, onSelectNode, filters }) {
  const svgRef = useRef();
  const [focusedNode, setFocusedNode] = useState(null);

  // 1. Filter the data BEFORE feeding it to D3
  const processedData = useMemo(() => {
    if (!graphData || !graphData.nodes) return { nodes: [], links: [] };

    // Filter Nodes based on UI toggles
    const filteredNodes = graphData.nodes.filter(node => {
      if (filters.criticalOnly && node.threatLevel !== "Elevated") return false;
      if (!filters.showInfrastructure && node.type === "Infrastructure") return false;
      if (!filters.showDomains && (node.type === "Domain" || node.type === "Subdomain" || node.type === "Primary Target")) return false;
      return true;
    });

    const validNodeIds = new Set(filteredNodes.map(n => n.id));

    // Filter Links to only include connections where BOTH nodes are currently visible
    const filteredLinks = graphData.links.filter(link => 
      validNodeIds.has(link.source.id || link.source) && 
      validNodeIds.has(link.target.id || link.target)
    );

    // D3 modifies objects directly, so we deep copy them to prevent state corruption
    return {
      nodes: filteredNodes.map(d => ({ ...d })),
      links: filteredLinks.map(d => ({ ...d }))
    };
  }, [graphData, filters]);


  useEffect(() => {
    if (processedData.nodes.length === 0) {
      d3.select(svgRef.current).selectAll("*").remove();
      return;
    }

    const width = 800;
    const height = 500;

    d3.select(svgRef.current).selectAll("*").remove();

    const svg = d3.select(svgRef.current)
      .attr("viewBox", `0 0 ${width} ${height}`)
      .style("background-color", "#0b0c10");

    const g = svg.append("g");

    svg.call(d3.zoom().on("zoom", (event) => g.attr("transform", event.transform)));

    const simulation = d3.forceSimulation(processedData.nodes)
      .force("link", d3.forceLink(processedData.links).id(d => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collide", d3.forceCollide().radius(20)); // Prevents nodes from overlapping

    // 2. Pre-calculate adjacency matrix for Focus Mode
    const linkedByIndex = {};
    processedData.links.forEach(d => {
      linkedByIndex[`${d.source.id},${d.target.id}`] = true;
      linkedByIndex[`${d.target.id},${d.source.id}`] = true;
    });

    const isConnected = (a, b) => {
      return linkedByIndex[`${a.id},${b.id}`] || linkedByIndex[`${b.id},${a.id}`] || a.id === b.id;
    };

    const link = g.append("g")
      .selectAll("line")
      .data(processedData.links)
      .join("line")
      .attr("stroke", "#45f3ff")
      .attr("stroke-opacity", d => {
        if (!focusedNode) return 0.6;
        return (d.source.id === focusedNode.id || d.target.id === focusedNode.id) ? 1 : 0.05;
      })
      .attr("stroke-width", d => {
        if (!focusedNode) return 2;
        return (d.source.id === focusedNode.id || d.target.id === focusedNode.id) ? 3 : 1;
      });

    const node = g.append("g")
      .selectAll("circle")
      .data(processedData.nodes)
      .join("circle")
      .attr("r", d => d.threatLevel === "Elevated" ? 14 : 10)
      .attr("fill", d => d.threatLevel === "Elevated" ? "#ff4a4a" : "#66fcf1")
      .attr("stroke", "#fff")
      .attr("stroke-width", 1.5)
      .style("cursor", "crosshair")
      // Opacity check for Focus Mode
      .attr("opacity", d => {
        if (!focusedNode) return 1;
        return isConnected(d, focusedNode) ? 1 : 0.1;
      })
      .on("click", (event, d) => {
        // Toggle focus state: if clicking already focused node, unfocus it
        const newFocus = (focusedNode && focusedNode.id === d.id) ? null : d;
        setFocusedNode(newFocus);
        onSelectNode(d);
      })
      .call(d3.drag()
        .on("start", (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on("end", (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null; d.fy = null;
        })
      );

    const labels = g.append("g")
      .selectAll("text")
      .data(processedData.nodes)
      .join("text")
      .text(d => d.name)
      .attr("font-size", "10px")
      .attr("fill", "#c5c6c7")
      .attr("dx", 16)
      .attr("dy", 4)
      .attr("opacity", d => {
        if (!focusedNode) return 0.8;
        return isConnected(d, focusedNode) ? 1 : 0.05;
      });

    simulation.on("tick", () => {
      link.attr("x1", d => d.source.x).attr("y1", d => d.source.y).attr("x2", d => d.target.x).attr("y2", d => d.target.y);
      node.attr("cx", d => d.x).attr("cy", d => d.y);
      labels.attr("x", d => d.x).attr("y", d => d.y);
    });

    return () => simulation.stop();
  }, [processedData, focusedNode]);

  return (
    <div className="border border-secondary rounded overflow-hidden shadow">
      {/* Click background to clear focus */}
      <svg ref={svgRef} className="w-100 h-100" style={{ minHeight: "600px" }} onClick={(e) => {
        if (e.target.tagName === 'svg') setFocusedNode(null);
      }}/>
    </div>
  );
}