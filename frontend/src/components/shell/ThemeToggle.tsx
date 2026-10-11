import { Sun } from "lucide-react";
import { useEffect, useState } from "react";
import { currentTheme, setTheme, type Theme } from "@/lib/theme";

/** "Light mode" switch for the sidebar: on = the light colour scheme of the previous dashboard. */
export function ThemeToggle({ className = "" }: { className?: string }) {
  const [theme, setState] = useState<Theme>("dark");
  useEffect(() => setState(currentTheme()), []);
  const light = theme === "light";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={light}
      className={className}
      onClick={() => {
        const next = light ? "dark" : "light";
        setTheme(next);
        setState(next);
      }}
    >
      <Sun className="h-4 w-4" aria-hidden />
      Light mode
      <span
        aria-hidden
        className={`ml-auto flex h-4 w-7 items-center rounded-full p-0.5 transition ${light ? "bg-sidebar-primary" : "bg-sidebar-accent"}`}
      >
        <span
          className={`block h-3 w-3 rounded-full bg-sidebar-foreground transition ${light ? "translate-x-3" : ""}`}
        />
      </span>
    </button>
  );
}
