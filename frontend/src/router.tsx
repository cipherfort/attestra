// SPDX-License-Identifier: Apache-2.0
import { lazy } from "react";
import { Link, createBrowserRouter, useParams } from "react-router";
import { AppShell } from "./components/shell/AppShell";

// Each page is its own chunk, so the first load carries only the shell.
const Admin = lazy(() => import("./pages/Admin").then((m) => ({ default: m.Admin })));
const Application = lazy(() => import("./pages/Application").then((m) => ({ default: m.Application })));
const Assessments = lazy(() => import("./pages/Assessments").then((m) => ({ default: m.Assessments })));
const EvidencePage = lazy(() => import("./pages/Evidence").then((m) => ({ default: m.EvidencePage })));
const EvidenceExplorer = lazy(() => import("./pages/Evidence").then((m) => ({ default: m.EvidenceExplorer })));
const FindingPage = lazy(() => import("./pages/Findings").then((m) => ({ default: m.FindingPage })));
const FindingsList = lazy(() => import("./pages/Findings").then((m) => ({ default: m.FindingsList })));
const Exceptions = lazy(() => import("./pages/Exceptions").then((m) => ({ default: m.Exceptions })));
const Integrations = lazy(() => import("./pages/Integrations").then((m) => ({ default: m.Integrations })));
const CvePage = lazy(() => import("./pages/SupplyChain").then((m) => ({ default: m.CvePage })));
const SupplyChain = lazy(() => import("./pages/SupplyChain").then((m) => ({ default: m.SupplyChain })));
const Controls = lazy(() => import("./pages/Controls").then((m) => ({ default: m.Controls })));
const Maturity = lazy(() => import("./pages/Maturity").then((m) => ({ default: m.Maturity })));
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
const ControlsRoute = () => <Controls id={useParams().id} />;
const ExceptionsRoute = () => { const id = useParams().id; return <Exceptions key={id ?? ""} id={id} />; };
const AssessmentsRoute = () => { const id = useParams().id; return <Assessments key={id ?? ""} id={id} />; };

function NotFound() {
  return (
    <div className="py-16 text-center">
      <h1 className="m-0">Page not found</h1>
      <p className="m-0 mt-2 text-muted">There is nothing at this address. <Link to="/">Go to the overview</Link>.</p>
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
      { path: "findings", element: <FindingsList /> },
      { path: "findings/:id", element: <FindingRoute /> },
      { path: "evidence", element: <EvidenceExplorer /> },
      { path: "evidence/view/:tab", element: <EvidenceExplorer /> },
      { path: "evidence/:id", element: <EvidenceRoute /> },
      { path: "supply-chain", element: <SupplyChain /> },
      { path: "supply-chain/:tab", element: <SupplyChain /> },
      { path: "cve", element: <CveRoute /> },
      { path: "cve/:id", element: <CveRoute /> },
      { path: "controls", element: <ControlsRoute /> },
      { path: "controls/:id", element: <ControlsRoute /> },
      { path: "maturity", element: <Maturity /> },
      { path: "leadership", element: <Leadership /> },
      { path: "exceptions", element: <ExceptionsRoute /> },
      { path: "exceptions/:id", element: <ExceptionsRoute /> },
      { path: "assessments", element: <AssessmentsRoute /> },
      { path: "assessments/:id", element: <AssessmentsRoute /> },
      { path: "integrations", element: <Integrations /> },
      { path: "integrations/:key", element: <Integrations /> },
      { path: "admin", element: <Admin /> },
      { path: "admin/:tab", element: <Admin /> },
      { path: "*", element: <NotFound /> },
    ],
  },
]);

/** Navigate from event handlers outside a component's router context (pages that predate the router). */
export function go(path: string): void {
  void router.navigate(path);
}
