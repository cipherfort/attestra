// SPDX-License-Identifier: Apache-2.0
import { createBrowserRouter, Navigate, useParams } from "react-router";
import { AppShell } from "./components/shell/AppShell";
import { Admin } from "./pages/Admin";
import { Application } from "./pages/Application";
import { Assessments } from "./pages/Assessments";
import { EvidencePage, FindingPage } from "./pages/Detail";
import { Exceptions } from "./pages/Exceptions";
import { Integrations } from "./pages/Integrations";
import { CvePage, Leadership } from "./pages/Org";
import { Portfolio } from "./pages/Portfolio";
import { Register } from "./pages/Register";

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
      { index: true, element: <Navigate to="/apps" replace /> },
      { path: "apps", element: <Portfolio /> },
      { path: "apps/:id", element: <AppRoute /> },
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
