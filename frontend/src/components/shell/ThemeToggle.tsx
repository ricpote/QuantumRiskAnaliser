import { Sun } from "lucide-react";
import { useSyncExternalStore } from "react";
import { currentTheme, setTheme, subscribeTheme } from "@/lib/theme";

/** "Light mode" switch for the sidebar: on = the light colour scheme of the previous dashboard. */
export function ThemeToggle({ className = "" }: { className?: string }) {
  // read from <html>, so the sidebar and phone-menu switches always agree (server render: dark)
  const light = useSyncExternalStore(subscribeTheme, currentTheme, () => "dark") === "light";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={light}
      className={className}
      onClick={() => setTheme(light ? "dark" : "light")}
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
