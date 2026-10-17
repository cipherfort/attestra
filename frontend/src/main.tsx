// SPDX-License-Identifier: Apache-2.0
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono/400.css";
import "./styles/app.css";
import { Layout, useRoute } from "./components/layout";
import { Admin } from "./pages/Admin";
import { Application } from "./pages/Application";
import { Assessments } from "./pages/Assessments";
import { EvidencePage, FindingPage } from "./pages/Detail";
import { Exceptions } from "./pages/Exceptions";
import { Integrations } from "./pages/Integrations";
import { CvePage, Leadership } from "./pages/Org";
import { Portfolio } from "./pages/Portfolio";
import { Register } from "./pages/Register";

function App() {
  const route = useRoute();
  const [section, id] = route;
  let page;
  switch (section) {
    case "apps": page = id ? <Application id={id} /> : <Portfolio />; break;
    case "findings": page = id ? <FindingPage id={id} /> : <Portfolio />; break;
    case "evidence": page = id ? <EvidencePage id={id} /> : <Portfolio />; break;
    case "cve": page = <CvePage initial={id} />; break;
    case "leadership": page = <Leadership />; break;
    case "integrations": page = <Integrations />; break;
    case "register": page = <Register />; break;
    case "exceptions": page = <Exceptions id={id} />; break;
    case "assessments": page = <Assessments id={id} />; break;
    case "admin": page = <Admin />; break;
    default: page = <Portfolio />;
  }
  return <Layout route={route}>{page}</Layout>;
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
