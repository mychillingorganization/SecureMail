import { createBrowserRouter, redirect } from "react-router";

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
  {
    path: "/scanner/",
    lazy: async () => {
      const mod = await import("./components/EmailScanner");
      return { Component: mod.EmailScanner };
    },
  },
  {
    path: "/chat",
    lazy: async () => {
      const mod = await import("./components/ChatPage");
      return { Component: mod.ChatPage };
    },
  },
  {
    path: "/list",
    lazy: async () => {
      const mod = await import("./components/WhitelistBlacklistPage");
      return { Component: mod.WhitelistBlacklistPage };
    },
  },
  {
    path: "*",
    loader: () => redirect("/scanner"),
  },
]);
