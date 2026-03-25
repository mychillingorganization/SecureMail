import { createBrowserRouter } from "react-router";
import { Dashboard } from "./components/Dashboard";
import { EmailScanner } from "./components/EmailScanner";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Dashboard,
  },
  {
    path: "/scanner",
    Component: EmailScanner,
  },
]);
