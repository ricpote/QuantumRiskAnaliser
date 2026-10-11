import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { ThemeToggle } from "@/components/shell/ThemeToggle";
import { THEME_KEY, themeScript } from "@/lib/theme";

afterEach(() => {
  cleanup();
  document.documentElement.classList.remove("light");
  localStorage.clear();
});

it("switches to the light scheme and back, remembering the choice", () => {
  render(<ThemeToggle />);
  const toggle = screen.getByRole("switch", { name: "Light mode" });
  expect(toggle).toHaveAttribute("aria-checked", "false");
  fireEvent.click(toggle);
  expect(document.documentElement).toHaveClass("light");
  expect(localStorage.getItem(THEME_KEY)).toBe("light");
  expect(toggle).toHaveAttribute("aria-checked", "true");
  fireEvent.click(toggle);
  expect(document.documentElement).not.toHaveClass("light");
  expect(localStorage.getItem(THEME_KEY)).toBe("dark");
});

it("applies a saved light theme before React starts, and stays dark by default", () => {
  new Function(themeScript)();
  expect(document.documentElement).not.toHaveClass("light");
  localStorage.setItem(THEME_KEY, "light");
  new Function(themeScript)();
  expect(document.documentElement).toHaveClass("light");
  render(<ThemeToggle />);
  expect(screen.getByRole("switch", { name: "Light mode" })).toHaveAttribute(
    "aria-checked",
    "true",
  );
});

it("keeps every theme switch on the page in sync", () => {
  render(
    <>
      <ThemeToggle />
      <ThemeToggle />
    </>,
  );
  const [sidebar, phone] = screen.getAllByRole("switch", { name: "Light mode" });
  fireEvent.click(phone!);
  expect(sidebar).toHaveAttribute("aria-checked", "true");
});
