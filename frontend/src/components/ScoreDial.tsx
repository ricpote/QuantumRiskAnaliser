import { animate, motion, useMotionValue, useReducedMotion, useTransform } from "framer-motion";
import { useEffect, useRef } from "react";
import { scoreTone } from "@/lib/labels";

// Grade bands drawn on the dial (the grade itself always comes from the report).
const BANDS = [
  { g: "F", min: 0 },
  { g: "E", min: 25 },
  { g: "D", min: 40 },
  { g: "C", min: 55 },
  { g: "B", min: 70 },
  { g: "A", min: 85 },
] as const;
const toneFill = { critical: "fill-critical", medium: "fill-medium", safe: "fill-safe" } as const;

function polar(rad: number, v: number): [number, number] {
  const a = Math.PI * (1 - v / 100);
  return [200 + rad * Math.cos(a), 200 - rad * Math.sin(a)];
}
function arc(v0: number, v1: number, rad: number) {
  const [x0, y0] = polar(rad, v0),
    [x1, y1] = polar(rad, v1);
  return `M${x0} ${y0} A${rad} ${rad} 0 0 1 ${x1} ${y1}`;
}

/** Score instrument: grade bands on an arc, the needle points at the score. Value and grade come from the report. */
export function ScoreDial({
  score,
  grade,
  caption,
  label = "Quantum Readiness Score",
}: {
  score: number;
  grade?: string | undefined;
  caption?: string | undefined;
  label?: string;
}) {
  const reduce = useReducedMotion();
  // Needle position in score units (0 = left, 100 = right); the tip stays on the arc so it pivots on the centre pin.
  const v = useMotionValue(reduce ? score : 0);
  const first = useRef(true);
  useEffect(() => {
    const delay = first.current && !reduce ? 0.35 : 0;
    first.current = false;
    const c = animate(
      v,
      score,
      reduce ? { duration: 0 } : { type: "spring", stiffness: 60, damping: 11, delay },
    );
    return () => c.stop();
  }, [score, reduce, v]);
  const tipX = useTransform(v, (n) => polar(128, n)[0]);
  const tipY = useTransform(v, (n) => polar(128, n)[1]);
  const dotX = useTransform(v, (n) => polar(132, n)[0]);
  const dotY = useTransform(v, (n) => polar(132, n)[1]);
  return (
    <figure className="panel grid-paper px-4 pb-2 pt-3">
      <svg
        viewBox="0 0 400 250"
        className="w-full"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={score}
        aria-valuetext={`${score} out of 100${grade ? `, grade ${grade}` : ""}`}
      >
        {BANDS.map((b, i) => {
          const max = BANDS[i + 1]?.min ?? 100;
          const on = grade === b.g;
          const [lx, ly] = polar(184, (b.min + max) / 2);
          return (
            <g key={b.g}>
              <motion.path
                d={arc(b.min + 0.6, max - 0.6, 152)}
                fill="none"
                strokeWidth={on ? 24 : 14}
                className={i < 2 ? "stroke-critical" : i < 4 ? "stroke-medium" : "stroke-safe"}
                strokeOpacity={on ? 1 : 0.3}
                style={{ transition: "all .5s" }}
                initial={reduce ? false : { pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 0.4, delay: i * 0.1 }}
              />
              <text
                x={lx}
                y={ly}
                textAnchor="middle"
                dominantBaseline="middle"
                className="fill-foreground font-display"
                fontSize={on ? 24 : 15}
                opacity={on ? 1 : 0.55}
                style={{ transition: "all .5s" }}
              >
                {b.g}
              </text>
            </g>
          );
        })}
        {Array.from({ length: 21 }, (_, i) => {
          const [a1, b1] = polar(140, i * 5),
            [a2, b2] = polar(i % 2 ? 134 : 128, i * 5);
          return (
            <line
              key={i}
              x1={a1}
              y1={b1}
              x2={a2}
              y2={b2}
              strokeWidth={1}
              className="stroke-muted-foreground"
              opacity={0.6}
            />
          );
        })}
        <motion.line
          x1={200}
          y1={200}
          x2={tipX}
          y2={tipY}
          strokeWidth={3}
          strokeLinecap="round"
          className="stroke-primary"
        />
        <motion.circle cx={dotX} cy={dotY} r={4} className="fill-primary" />
        <circle cx={200} cy={200} r={6} className="fill-primary" />
        <text
          x={200}
          y={238}
          textAnchor="middle"
          className={`font-display ${toneFill[scoreTone(score)]}`}
          fontWeight={600}
          fontSize={40}
          data-tone={scoreTone(score)}
        >
          {score}
        </text>
      </svg>
      {caption && (
        <figcaption className="-mt-1 border-t border-border pt-2 text-center text-sm text-muted-foreground">
          {caption}
        </figcaption>
      )}
    </figure>
  );
}
