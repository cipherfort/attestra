// SPDX-License-Identifier: Apache-2.0
import { lazy } from "react";
import { createBrowserRouter, useParams } from "react-router";
import { AppShell } from "./components/shell/AppShell";

// Each page is its own chunk, so the first load carries only the shell.
const Admin = lazy(() => import("./pages/Admin").then((m) => ({ default: m.Admin })));
const Application = lazy(() => import("./pages/Application").then((m) => ({ default: m.Application })));
const Assessments = lazy(() => import("./pages/Assessments").then((m) => ({ default: m.Assessments })));
const EvidencePage = lazy(() => import("./pages/Detail").then((m) => ({ default: m.EvidencePage })));
const FindingPage = lazy(() => import("./pages/Detail").then((m) => ({ default: m.FindingPage })));
const Exceptions = lazy(() => import("./pages/Exceptions").then((m) => ({ default: m.Exceptions })));
const Integrations = lazy(() => import("./pages/Integrations").then((m) => ({ default: m.Integrations })));
const CvePage = lazy(() => import("./pages/Org").then((m) => ({ default: m.CvePage })));
const Leadership = lazy(() => import("./pages/Org").then((m) => ({ default: m.Leadership })));
const Portfolio = lazy(() => import("./pages/Portfolio").then((m) => ({ default: m.Portfolio })));
const Register = lazy(() => import("./pages/Register").then((m) => ({ default: m.Register })));
const Overview = lazy(() => import("./pages/Overview").then((m) => ({ default: m.Overview })));

function useId(): string {
  return useParams().id ?? "";
}
const AppRoute = () => { const id = useId(); return <Application key={id} id={id} />; };
const FindingRoute = () => { const id = useId(); return <FindingPage key={id} id={id} />; };
const EvidenceRoute = () => { const id = useId(); return <EvidencePage key={id} id={id} />; };
const CveRoute = () => { const id = useParams().id; return <CvePage key={id ?? ""} initial={id} />; };
const ExceptionsRoute = () => { const id = useParams().id; return <Exceptions key={id ?? ""} id={id} />; };
const AssessmentsRoute = () => { const id = useParams().id; return <Assessments key={id ?? ""} id={id} />; };

function NotFound() {
  return (
    <div className="py-16 text-center">
      <h1>Page not found</h1>
      <p className="muted">There is nothing at this address. <a href="/apps">Go to applications</a>.</p>
    </div>
  );
}

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppShell />,
    children: [
      { index: true, element: <Overview /> },
      { path: "apps", element: <Portfolio /> },
      { path: "apps/:id", element: <AppRoute /> },
      { path: "apps/:id/:tab", element: <AppRoute /> },
      { path: "register", element: <Register /> },
      { path: "findings/:id", element: <FindingRoute /> },
      { path: "evidence/:id", element: <EvidenceRoute /> },
      { path: "cve", element: <CveRoute /> },
      { path: "cve/:id", element: <CveRoute /> },
      { path: "leadership", element: <Leadership /> },
      { path: "exceptions", element: <ExceptionsRoute /> },
      { path: "exceptions/:id", element: <ExceptionsRoute /> },
      { path: "assessments", element: <AssessmentsRoute /> },
      { path: "assessments/:id", element: <AssessmentsRoute /> },
      { path: "integrations", element: <Integrations /> },
      { path: "admin", element: <Admin /> },
      { path: "*", element: <NotFound /> },
    ],
  },
]);

/** Navigate from event handlers outside a component's router context (pages that predate the router). */
export function go(path: string): void {
  void router.navigate(path);
}
