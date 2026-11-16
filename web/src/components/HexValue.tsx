import { useState } from "react";
import { abbreviateHex } from "../model/workbench-model.ts";

interface HexValueProps {
  readonly value: string;
  readonly label: string;
}

export function HexValue({ value, label }: HexValueProps) {
  const [expanded, setExpanded] = useState(false);
  const short = abbreviateHex(value);
  if (short === value) {
    return <code className="hex">{value}</code>;
  }
  return (
    <span className="hex-value">
      <code className="hex" data-hex-expanded={expanded ? "true" : undefined}>
        {expanded ? value : short}
      </code>
      <button
        type="button"
        className="hex-toggle"
        aria-expanded={expanded}
        aria-label={`${expanded ? "Collapse" : "Expand"} ${label}`}
        onClick={() => setExpanded((open) => !open)}
      >
        {expanded ? "Collapse" : "Expand"}
      </button>
    </span>
  );
}
