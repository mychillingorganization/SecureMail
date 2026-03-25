import { createBrowserRouter } from "react-router";

export const router = createBrowserRouter([
  {
    path: "/",
    lazy: async () => {
      const mod = await import("./components/Dashboard");
      return { Component: mod.Dashboard };
    },
  },
  {
    path: "/scanner",
    lazy: async () => {
      const mod = await import("./components/EmailScanner");
      return { Component: mod.EmailScanner };
    },
  },
]);
